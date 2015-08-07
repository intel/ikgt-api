/*******************************************************************************
* Copyright (c) 2015 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#include "file_codes.h"
#define MON_DEADLOOP()          MON_DEADLOOP_LOG(XMON_VIEW_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(XMON_VIEW_C, __condition)
#include "vmcs_init.h"
#include "guest_cpu.h"
#include "guest.h"
#include "memory_allocator.h"
#include "gpm_api.h"
#include "ept_hw_layer.h"
#include "ept.h"
#include "mon_objects.h"
#include "guest_internal.h"
#include "guest_cpu_internal.h"
#include "xmon_internal.h"
#include "unrestricted_guest.h"


extern boolean_t
mon_mam_overwrite_permissions_in_existing_mapping(IN mam_handle_t mam_handle,
						  IN uint64_t src_addr,
						  IN uint64_t size,
						  IN mam_attributes_t attrs);

/* Note: This function is called to set the MON state before guest OS is
 *       launched. At this point, only BSP has been initialized and APs
 *       have not yet started. Cannot use scheduler functions to obtain
 *       guest_cpu_handle_t since gcpu is not yet initialized. */
void xmon_set_mon_state_before_guest_launch(guest_id_t guest_id,
					    view_handle_t view)
{
	guest_cpu_handle_t gcpu;
	guest_gcpu_econtext_t gcpu_context;
	guest_handle_t guest;
	guest_view_t *guest_view = (guest_view_t *)view;

	guest = mon_guest_handle(guest_id);
	MON_ASSERT(guest);
	MON_ASSERT(view);

	for (gcpu = mon_guest_gcpu_first(guest, &gcpu_context);
	     gcpu; gcpu = mon_guest_gcpu_next(&gcpu_context)) {
		/* Set GPM/EPT pointer (of each GCPU) to the View GPM/EPT */
		mon_gcpu_set_current_gpm(gcpu, guest_view->gpm);
		mon_ept_set_current_ept(gcpu, guest_view->ept_root_table_hpa,
			guest_view->gaw);
	}
}

boolean_t xmon_set_active_view(const guest_vcpu_t *vcpu_id, view_handle_t view,
			       boolean_t update_hw, uint64_t eptp_list_index)
{
	guest_view_t *guest_view = (guest_view_t *)view;
	boolean_t status = TRUE;
	mon_controls_t value;
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);

	if (update_hw && mon_ept_is_ept_enabled(gcpu)) {
		/* Set the EPTP in the VMCS (Hardware) */
		value.value = 0;
		value.ept_value.ept_root_table_hpa =
			guest_view->ept_root_table_hpa;
		value.ept_value.gaw = (uint64_t)guest_view->gaw;
		status = xmon_set_vmcs_control_state(vcpu_id,
			MON_EPTP_ADDRESS,
			&value);
	}

	if (mon_ve_is_hw_supported() && mon_ve_is_ve_enabled(gcpu)) {
		value.value = eptp_list_index;
		if (!xmon_set_vmcs_control_state(vcpu_id, MON_EPTP_INDEX,
			    &value)) {
			status = FALSE;
		}
	}

	if (status) {
		/* Update the MON state on current processor (GPM and EPT) */
		mon_gcpu_set_current_gpm(gcpu, guest_view->gpm);
		mon_ept_set_current_ept(gcpu, guest_view->ept_root_table_hpa,
			guest_view->gaw);
	}

	return status;
}

void xmon_invalidate_view(cpu_id_t from UNUSED, void *arg)
{
	guest_view_t *guest_view = NULL;
	guest_handle_t guest;
	ept_invept_cmd_t invept_cmd;
	view_invalidation_data_t *view_invalidation_data =
		(view_invalidation_data_t *)arg;

	MON_ASSERT(view_invalidation_data);

	guest = mon_guest_handle(view_invalidation_data->guest_id);
	MON_ASSERT(guest);
	guest_view = (guest_view_t *)view_invalidation_data->view;
	MON_ASSERT(guest_view);

	invept_cmd.host_cpu_id = ANY_CPU_ID;
	invept_cmd.cmd = INVEPT_CONTEXT_WIDE;
	invept_cmd.eptp = mon_ept_compute_eptp(guest,
		guest_view->ept_root_table_hpa,
		guest_view->gaw);
	mon_ept_invalidate_ept(ANY_CPU_ID, (void *)&invept_cmd);
}

void xmon_notify_mon_about_view_recreation(cpu_id_t from UNUSED, void *arg)
{
	cpu_id_t guest_id = (cpu_id_t)(size_t)arg;
	guest_cpu_handle_t gcpu = mon_scheduler_get_current_gcpu_for_guest(
		guest_id);

	if (!gcpu) {
		/* no gcpu for the current guest on the current host cpu */
		return;
	}

	/* Update Flat Page Tables */
	mon_gcpu_physical_memory_modified(gcpu);
}

static
void view_destroy_guest_address_space(view_handle_t view)
{
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(guest_view);

	if (MAM_INVALID_HANDLE != guest_view->address_space) {
		mon_mam_destroy_mapping(guest_view->address_space);
		guest_view->address_space = MAM_INVALID_HANDLE;
	}
}

boolean_t xmon_recreate_view(guest_id_t guest_id, view_handle_t view,
			     uint64_t eptp_list_index)
{
	boolean_t status = FALSE;
	guest_view_t *guest_view = (view_handle_t)view;
	guest_handle_t guest = mon_guest_handle(guest_id);

	MON_ASSERT(guest);
	MON_ASSERT(guest_view);

	view_destroy_guest_address_space(view);
	guest_view->address_space = mon_ept_create_guest_address_space(
		guest_view->gpm, TRUE);
	MON_ASSERT(guest_view->address_space != MAM_INVALID_HANDLE);

	status = mon_mam_convert_to_ept(guest_view->address_space,
		mon_ept_get_mam_super_page_support(),
		mon_ept_get_mam_supported_gaw(guest_view->gaw),
		mon_ve_is_hw_supported(),
		&(guest_view->ept_root_table_hpa));

	if (!mon_fvs_add_entry_to_eptp_list(guest,
		    guest_view->ept_root_table_hpa,
		    guest_view->gaw,
		    eptp_list_index)) {
		MON_LOG(mask_anonymous,
			level_trace,
			"Failed to add entry into eptp list hpa=0x%X  index=%d\n",
			guest_view->ept_root_table_hpa,
			eptp_list_index);
	}

	return status;
}

boolean_t xmon_update_view(const guest_vcpu_t *vcpu_id, view_handle_t view,
			   view_update_type_t update_type, gpa_t base_gpa,
			   hpa_t base_hpa, mam_attributes_t attr,
			   uint64_t eptp_list_index)
{
	boolean_t status;
	gpa_t align_base_gpa;
	mam_attributes_t old_attr;
	hpa_t hpa = 0, align_base_hpa;
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(vcpu_id);
	MON_ASSERT(guest_view);

	/* ensure address is aligned */
	align_base_gpa = ALIGN_BACKWARD(base_gpa, PAGE_4KB_SIZE);

	/* Remove mapping and return */
	if (update_type == VIEW_REMOVE_MAPPING) {
		status = mon_gpm_remove_mapping(guest_view->gpm, align_base_gpa,
			PAGE_4KB_SIZE);
		MON_ASSERT(status);
		return status;
	}

	if (update_type == VIEW_UPDATE_PERMISSIONS_ONLY) {
		status = mon_gpm_gpa_to_hpa(guest_view->gpm, align_base_gpa,
			&hpa, &old_attr);
		MON_ASSERT(status);
	} else if (update_type == VIEW_UPDATE_MAPPING) {
		hpa = base_hpa;
	}

	/* ensure address is aligned */
	align_base_hpa = ALIGN_BACKWARD(hpa, PAGE_4KB_SIZE);

	status = mon_gpm_add_mapping(guest_view->gpm, align_base_gpa,
		align_base_hpa, PAGE_4KB_SIZE, attr);
	MON_ASSERT(status);

	if (update_type == VIEW_UPDATE_PERMISSIONS_ONLY) {
		/* Optimization - Update EPT as well if only permissions are updated */
		if (guest_view->address_space == MAM_INVALID_HANDLE) {
			if (xmon_recreate_view(vcpu_id->guest_id,
				    (view_handle_t)guest_view,
				    eptp_list_index) == FALSE) {
				return FALSE;
			}
		}

		status = mon_mam_overwrite_permissions_in_existing_mapping(
			guest_view->address_space, align_base_gpa,
			PAGE_4KB_SIZE, attr);
		MON_ASSERT(status);
	}

	return status;
}

boolean_t xmon_remove_view(const guest_vcpu_t *vcpu_id, view_handle_t view,
			   uint64_t eptp_list_index)
{
	guest_view_t *guest_view = (guest_view_t *)view;
	guest_handle_t guest = mon_guest_handle(vcpu_id->guest_id);

	MON_ASSERT(guest_view);

	/* Reset GPM for view to "RO" permissions */
	mon_gpm_copy(mon_guest_get_startup_gpm(guest), guest_view->gpm, TRUE,
		mam_ro_attrs);
	/* Destroy the address space (EPT) */
	view_destroy_guest_address_space(view);

	if (!mon_fvs_delete_entry_from_eptp_list(guest, eptp_list_index)) {
		MON_LOG(mask_anonymous,
			level_error,
			"Failed to delete entry from eptp list %d\n",
			eptp_list_index);
	}

	return TRUE;
}

boolean_t xmon_remove_copied_view(guest_id_t guest_id, view_handle_t view,
				  uint64_t eptp_list_index)
{
	guest_view_t *guest_view = (guest_view_t *)view;
	guest_handle_t guest = mon_guest_handle(guest_id);

	MON_ASSERT(guest_view);
	MON_ASSERT(guest);

	/* Destroy the address space (EPT)
	 * This function will take care of the scenario if the current
	 * ept_root_table_hpa is set to Default EPT and will not free it */
	view_destroy_guest_address_space(view);

	guest_view->gpm = GPM_INVALID_HANDLE;
	guest_view->ept_root_table_hpa = 0;
	guest_view->gaw = (uint32_t)-1;

	if (!mon_fvs_delete_entry_from_eptp_list(guest, eptp_list_index)) {
		MON_LOG(mask_anonymous,
			level_error,
			"Failed to delete entry from eptp list %d\n",
			eptp_list_index);
	}

	return TRUE;
}

view_handle_t xmon_initialize_view(void)
{
	guest_view_t *guest_view;

	guest_view = (guest_view_t *)mon_malloc(sizeof(guest_view_t));
	MON_ASSERT(guest_view);

	guest_view->gpm = GPM_INVALID_HANDLE;
	guest_view->address_space = MAM_INVALID_HANDLE;
	guest_view->ept_root_table_hpa = 0;
	guest_view->gaw = (uint32_t)-1;

	return (view_handle_t)guest_view;
}

void xmon_create_view(guest_id_t guest_id, view_handle_t view,
		      boolean_t override_perms, mam_attributes_t perms,
		      uint64_t eptp_list_index)
{
	guest_view_t *guest_view = (guest_view_t *)view;
	guest_handle_t guest = mon_guest_handle(guest_id);
	boolean_t status;

	MON_ASSERT(guest);
	MON_ASSERT(guest_view);

	if (guest_view->gpm == GPM_INVALID_HANDLE) {
		guest_view->gpm = mon_gpm_create_mapping();
		MON_ASSERT(guest_view->gpm != GPM_INVALID_HANDLE);
	}

	if (guest_view->gaw == (uint32_t)-1) {
		guest_view->gaw = mon_ept_hw_get_guest_address_width(
			mon_ept_get_guest_address_width(guest_view->gpm));
		MON_ASSERT(guest_view->gaw != (uint32_t)-1);
	}

	mon_gpm_copy(mon_guest_get_startup_gpm(guest), guest_view->gpm,
		override_perms, perms);

	/* Sanity check: Will free memory if the View was not removed properly */
	status = xmon_recreate_view(guest_id, view, eptp_list_index);
	MON_ASSERT(status);

	return;
}

void xmon_copy_view(guest_id_t guest_id, view_handle_t *dst_view,
		    view_handle_t src_view, boolean_t original_perms,
		    uint64_t eptp_list_index)
{
	guest_view_t *dst_guest_view = (guest_view_t *)*dst_view;
	guest_view_t *src_guest_view = (guest_view_t *)src_view;
	guest_handle_t guest = mon_guest_handle(guest_id);

	MON_ASSERT(src_guest_view);
	MON_ASSERT(dst_guest_view);
	MON_ASSERT(guest);

	/* Sanity check: Free memory if the View was not removed properly */
	xmon_remove_copied_view(guest_id, *dst_view, eptp_list_index);

	dst_guest_view->gpm = src_guest_view->gpm;

	dst_guest_view->gaw = mon_ept_hw_get_guest_address_width(
		mon_ept_get_guest_address_width(dst_guest_view->gpm));
	MON_ASSERT(dst_guest_view->gaw != (uint32_t)-1);

	dst_guest_view->address_space = mon_ept_create_guest_address_space(
		dst_guest_view->gpm, original_perms);
	MON_ASSERT(mon_mam_convert_to_ept(dst_guest_view->address_space,
			mon_ept_get_mam_super_page_support(),
			mon_ept_get_mam_supported_gaw(dst_guest_view->gaw),
			mon_ve_is_hw_supported(),
			&(dst_guest_view->ept_root_table_hpa)));

	if (!mon_fvs_update_entry_in_eptp_list(guest,
		    dst_guest_view->ept_root_table_hpa,
		    dst_guest_view->gaw,
		    eptp_list_index)) {
		MON_LOG(mask_anonymous,
			level_trace,
			"Failed to update entry in eptp list hpa=0x%X  index=%d\n",
			dst_guest_view->ept_root_table_hpa,
			eptp_list_index);
	}

	*dst_view = dst_guest_view;

	return;
}

boolean_t xmon_is_execute_only_supported(void)
{
	const vmcs_hw_constraints_t *hw_constraints =
		mon_vmcs_hw_get_vmx_constraints();
	ia32_vmx_ept_vpid_cap_t ept_cap = hw_constraints->ept_vpid_capabilities;

	return ept_cap.bits.x_only;
}

boolean_t xmon_gpa_to_hpa(const guest_vcpu_t *vcpu_id, view_handle_t view,
			  gpa_t gpa, hpa_t *hpa, mam_attributes_t *hpa_attrs)
{
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(guest_view);
	return mon_gpm_gpa_to_hpa(guest_view->gpm, gpa, hpa, hpa_attrs);
}

boolean_t xmon_hpa_to_gpa(const guest_vcpu_t *vcpu_id, view_handle_t view,
			  hpa_t hpa, gpa_t *gpa)
{
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(guest_view);
	return mon_gpm_hpa_to_gpa(guest_view->gpm, hpa, gpa);
}

boolean_t xmon_is_mmio_address(view_handle_t view, gpa_t gpa)
{
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(guest_view);
	return mon_gpm_is_mmio_address(guest_view->gpm, gpa);
}

boolean_t xmon_is_cpu_in_non_paged_mode(const guest_vcpu_t *vcpu_id)
{
	MON_ASSERT(vcpu_id);
	return mon_ept_is_cpu_in_non_paged_mode(vcpu_id->guest_id);
}

boolean_t xmon_is_fvs_enabled(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return mon_fvs_is_fvs_enabled(gcpu);
}

void xmon_enable_fvs(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	mon_fvs_enable_fvs(gcpu);
	return;
}

void xmon_disable_fvs(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	mon_fvs_disable_fvs(gcpu);
	return;
}

void xmon_enable_fvs_single_core(const guest_vcpu_t *vcpu_id, boolean_t enable)
{
	/* 1st arg is unused; fvs_enable_eptp_switching is callable by ipc,
	 * which provides the cpu id */
	cpu_id_t cpuid = 0;
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);
	guest_handle_t guest;

	MON_ASSERT(gcpu);
	guest = mon_gcpu_guest_handle(gcpu);

	if (enable) {
		mon_fvs_enable_eptp_switching(cpuid, guest);
	} else {
		mon_fvs_disable_eptp_switching(cpuid, guest);
	}
	return;
}

boolean_t xmon_enable_view(const guest_vcpu_t *vcpu_id, boolean_t enable)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	if (enable) {
		if (!mon_ept_is_ept_enabled(gcpu)) {
			if (mon_ept_enable(gcpu)) {
				/* enable UG */
				if (xmon_is_unrestricted_guest_supported()) {
					/* NOTE: vmcs cache keeps counters of number of enables
					 * and it can't be disabled until count goes to 0 */
					if (!IS_MODE_UNRESTRICTED_GUEST(gcpu)) {
						mon_unrestricted_guest_enable(
							gcpu);
					}
				}
			} else { /* ept enable failed */
				return FALSE;
			}
		}
	} else { /* disable view */
		 /* first disable UG */
		if (xmon_is_unrestricted_guest_supported()
		    && mon_is_unrestricted_guest_enabled(gcpu)) {
			mon_unrestricted_guest_disable(gcpu);
		}
		if (mon_ept_is_ept_enabled(gcpu)) {
			mon_ept_disable(gcpu);
		}
	}
	return TRUE;
}

hpa_t *xmon_get_eptp_list_paddress(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return mon_fvs_get_all_eptp_list_paddress(gcpu);
}

boolean_t xmon_get_ept_addr(view_handle_t view, uint64_t *ept_addr)
{
	guest_view_t *guest_view = (guest_view_t *)view;
	eptp_t eptp;
	uint32_t ept_gaw = 0;

	ept_gaw = mon_ept_hw_get_guest_address_width(guest_view->gaw);
	if (ept_gaw == (uint32_t)-1) {
		return FALSE;
	}
	eptp.bits.etmt = mon_ept_hw_get_ept_memory_type();
	eptp.bits.gaw = mon_ept_hw_get_guest_address_width_encoding(ept_gaw);
	eptp.bits.reserved = 0;

	*ept_addr = eptp.uint64;

	return TRUE;
}

void xmon_update_active_view(guest_cpu_handle_t gcpu)
{
	uint64_t vmexit_eptp, ieptp;
	uint64_t handle;
	vmcs_object_t *vmcs = mon_gcpu_get_vmcs(gcpu);
	const guest_vcpu_t *vcpu_id = xmon_get_guest_vcpu();

	MON_ASSERT(vcpu_id);

	vmexit_eptp = mon_vmcs_read(vmcs, VMCS_EPTP_ADDRESS);

	/* check to see if view changed */
	if (vmexit_eptp == gcpu->fvs_cpu_desc.vmentry_eptp) {
		return;
	}

	/* view changed find the handle */
	for (handle = 0; handle < MAX_EPTP_ENTRIES; handle++) {
		ieptp = mon_fvs_get_eptp_entry(gcpu, handle);
		if (vmexit_eptp == ieptp) {
			if (g_plugin_handlers.fvs_set_active_view_event_handler) {
				g_plugin_handlers.
				fvs_set_active_view_event_handler(vcpu_id,
					handle,
					FALSE);
			}
			break;
		}
	}
}

void xmon_update_vmcs_eptp_address(guest_cpu_handle_t gcpu,
				   uint64_t eptp_list_index)
{
	vmcs_object_t *vmcs;
	uint64_t leptp;

	leptp = mon_fvs_get_eptp_entry(gcpu, eptp_list_index);

	if (leptp) {
		vmcs = mon_gcpu_get_vmcs(gcpu);
		mon_vmcs_write(vmcs, VMCS_EPTP_ADDRESS, leptp);
	}
}

boolean_t xmon_add_eptp_entry_single_core(const guest_vcpu_t *vcpu_id,
					  view_handle_t view,
					  uint64_t eptp_list_index)
{
	guest_handle_t guest = mon_guest_handle(vcpu_id->guest_id);
	guest_view_t *dst_view = (guest_view_t *)view;

	MON_ASSERT(guest);

	if (!dst_view) {
		return FALSE;
	}

	return mon_fvs_add_entry_to_eptp_list_single_core(guest,
		vcpu_id->guest_cpu_id,
		dst_view->ept_root_table_hpa,
		dst_view->gaw,
		eptp_list_index);
}

boolean_t xmon_delete_eptp_entry_single_core(const guest_vcpu_t *vcpu_id,
					     uint64_t eptp_list_index)
{
	guest_handle_t guest = mon_guest_handle(vcpu_id->guest_id);

	MON_ASSERT(guest);

	return mon_fvs_delete_entry_from_eptp_list_single_core(guest,
		vcpu_id->guest_cpu_id,
		eptp_list_index);
}

boolean_t xmon_delete_entry_from_eptp_list_all_cores(
	const guest_vcpu_t *vcpu_id,
	uint64_t eptp_list_index)
{
	guest_handle_t guest = mon_guest_handle(vcpu_id->guest_id);

	MON_ASSERT(guest);

	return mon_fvs_delete_entry_from_eptp_list(guest, eptp_list_index);
}

#ifdef DEBUG
void view_print(const guest_vcpu_t *vcpu_id, view_handle_t view)
{
	guest_view_t *guest_view = (guest_view_t *)view;

	MON_ASSERT(vcpu_id);
	MON_ASSERT(guest_view);
	mon_ept_print(mon_guest_handle(
			vcpu_id->guest_id), guest_view->address_space);
}
#endif
