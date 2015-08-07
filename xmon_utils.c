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
#define MON_DEADLOOP()          MON_DEADLOOP_LOG(XMON_UTILS_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(XMON_UTILS_C, __condition)
#include "mon_callback.h"
#include "xmon_internal.h"
#include "mon_dbg.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"
#include "guest.h"
#include "vmcall.h"
#include "host_memory_manager_api.h"
#include "unrestricted_guest.h"
#include "policy_manager.h"

/* Globals */
static xmon_cpu_state_t **g_xmon_cpu_state;
static uint32_t g_xmon_num_of_cpus;
xmon_event_handlers_t g_plugin_handlers = { NULL };

extern uint32_t g_msr_monitored_by_plugin[PLUGIN_MAX_MON_HANDLED_MSRS];

static
mon_status_t xmon_vmcall(guest_cpu_handle_t gcpu, address_t *arg1,
			 address_t *arg2 UNUSED, address_t *arg3 UNUSED)
{
	const guest_vcpu_t *vcpu_id = NULL;

	MON_ASSERT(gcpu);
	vcpu_id = get_guest_vcpu_from_gcpu(gcpu);
	if (!vcpu_id) {
		MON_LOG(mask_xmon_api, level_error,
			"Error : VM call handler argument invalid\n");
		return MON_ERROR;
	}
	set_xmon_state(gcpu, vcpu_id);

	if (!g_plugin_handlers.vmcall_event_handler) {
		return MON_ERROR;
	}

	return g_plugin_handlers.vmcall_event_handler(vcpu_id, arg1);
}

static
void register_plugin_vmcall(guest_data_t *guest_data)
{
	uint32_t i = 0;

	for (i = 0; (i < MAX_GUESTS_SUPPORTED_BY_XMON) &&
	     (guest_data[i].guest_id != INVALID_GUEST_ID); i++) {
		/* Register VMCALL_PLUGIN for all guests (primary and secondary) */
		mon_vmcall_register(guest_data[i].guest_id, VMCALL_PLUGIN,
			xmon_vmcall, FALSE);
	}
}

#ifdef PLUGIN_EXISTS
extern void plugin_init(void);
#else
void plugin_init(void)
{
	/* Dummy function to be filled if no plugin exists */
}
#endif

void xmon_register_handlers(xmon_event_handlers_t *plugin_handlers)
{
	/* Cache(copy) plugin handlers in evmm structure */
	g_plugin_handlers = *plugin_handlers;
}

static
boolean_t xmon_initialize(report_initialization_data_t *initialization_data)
{
	uint32_t i = 0, j = 0;
	boolean_t status = FALSE;

	if (NULL == initialization_data) {
		return FALSE;
	}
	MON_LOG(mask_xmon_api, level_trace,
		"%s: Initializing XMON API. Num of CPUs = %d\n",
		__FUNCTION__, initialization_data->num_of_cpus);

	g_xmon_num_of_cpus = initialization_data->num_of_cpus;
	/* Initialize xmon_cpu_state_t */
	g_xmon_cpu_state = (xmon_cpu_state_t **)mon_malloc(
		g_xmon_num_of_cpus * sizeof(xmon_cpu_state_t *));
	if (!g_xmon_cpu_state) {
		return FALSE;
	}

	for (i = 0; i < g_xmon_num_of_cpus; i++) {
		g_xmon_cpu_state[i] = (xmon_cpu_state_t *)mon_malloc(
			sizeof(xmon_cpu_state_t));
		if (!g_xmon_cpu_state[i]) {
			for (j = 0; j < i; j++)
				mon_mfree(g_xmon_cpu_state[j]);
			mon_mfree(g_xmon_cpu_state);
			return FALSE;
		}
		g_xmon_cpu_state[i]->gcpu = NULL;
		g_xmon_cpu_state[i]->vcpu_id = NULL;
	}

	plugin_init();

	/* Register plugin VMCALL */
	register_plugin_vmcall(initialization_data->guest_data);

	mon_memset(g_msr_monitored_by_plugin, 0,
		sizeof(g_msr_monitored_by_plugin));

	if (!g_plugin_handlers.initialize_event_handler) {
		return TRUE;
	}

	/* Initialize plugin event handler */
	status = g_plugin_handlers.initialize_event_handler(
		initialization_data->num_of_cpus,
		initialization_data->guest_data,
		initialization_data->mem_config);

	return status;
}

boolean_t report_mon_event(report_mon_event_t event,
			   mon_identification_data_t gcpu,
			   const guest_vcpu_t *vcpu_id,
			   void *event_specific_data)
{
	report_initialization_data_t *initialization_data = NULL;
	report_ept_violation_data_t *ept_violation_data = NULL;
	report_cr_dr_load_access_data_t *cr_dr_access_data = NULL;
	report_dtr_access_data_t *dtr_access_data = NULL;
	report_msr_write_access_data_t *msr_write_access_data = NULL;
	report_set_active_eptp_data_t *set_active_eptp_data = NULL;
	report_initial_vmexit_check_data_t *initial_vmexit_check_data = NULL;
	report_mon_teardown_data_t *mon_teardown_data = NULL;
	report_fast_view_switch_data_t *fast_view_switch_data = NULL;
	report_mon_log_event_data_t *mon_log_event_data = NULL;
	report_cpuid_data_t *cpuid_data = NULL;
	boolean_t status = FALSE;
	uint64_t msr_value = 0;

	if (event != MON_EVENT_INITIALIZATION_BEFORE_APS_STARTED) {
		/* NOTE: DO NOT USE gcpu and vcpu_id during initialization.
		 * gcpu is not yet initialized. */
		MON_ASSERT(vcpu_id);
		set_xmon_state(gcpu, vcpu_id);
	}
	switch (event) {
	case MON_EVENT_INITIALIZATION_BEFORE_APS_STARTED:
		/* NOTE: DO NOT USE gcpu and vcpu_id. gcpu is not yet
		 * initialized. */
		initialization_data =
			(report_initialization_data_t *)event_specific_data;
		status = xmon_initialize(initialization_data);
		break;
	case MON_EVENT_INITIALIZATION_AFTER_APS_STARTED:
		if (!g_plugin_handlers.
		    initialize_after_aps_started_event_handler) {
			status = TRUE;
		} else {
			initialization_data =
				(report_initialization_data_t *)
				event_specific_data;
			status =
				g_plugin_handlers.
				initialize_after_aps_started_event_handler(
					initialization_data->num_of_cpus,
					initialization_data->guest_data);
		}
		break;
	case MON_EVENT_EPT_VIOLATION:
		if (!g_plugin_handlers.ept_violation_event_handler) {
			status = TRUE;
		} else {
			ept_violation_data =
				(report_ept_violation_data_t *)
				event_specific_data;
			status = g_plugin_handlers.ept_violation_event_handler(
				vcpu_id, ept_violation_data->qualification,
				ept_violation_data->guest_linear_address,
				ept_violation_data->guest_physical_address);
		}
		break;
	case MON_EVENT_MTF_VMEXIT:
		if (!g_plugin_handlers.mtf_vmexit_event_handler) {
			status = TRUE;
		} else {
			status = g_plugin_handlers.mtf_vmexit_event_handler(
				vcpu_id);
		}
		break;
	case MON_EVENT_CR_ACCESS:
		if (!g_plugin_handlers.cr_access_event_handler) {
			status = FALSE;
		} else {
			cr_dr_access_data =
				(report_cr_dr_load_access_data_t *)
				event_specific_data;
			status = g_plugin_handlers.cr_access_event_handler(
				vcpu_id, cr_dr_access_data->qualification);
		}
		break;
	case MON_EVENT_DR_LOAD_ACCESS:
		if (!g_plugin_handlers.dr_load_event_handler) {
			status = TRUE;
		} else {
			cr_dr_access_data =
				(report_cr_dr_load_access_data_t *)
				event_specific_data;
			status = g_plugin_handlers.dr_load_event_handler(
				vcpu_id, cr_dr_access_data->qualification);
		}
		break;
	case MON_EVENT_LDTR_LOAD_ACCESS:
		if (!g_plugin_handlers.ldtr_load_event_handler) {
			status = TRUE;
		} else {
			dtr_access_data =
				(report_dtr_access_data_t *)event_specific_data;
			status = g_plugin_handlers.ldtr_load_event_handler(
				vcpu_id, dtr_access_data->qualification,
				dtr_access_data->instruction_info);
		}
		break;
	case MON_EVENT_GDTR_IDTR_ACCESS:
		if (!g_plugin_handlers.gdtr_idtr_access_event_handler) {
			status = TRUE;
		} else {
			dtr_access_data =
				(report_dtr_access_data_t *)event_specific_data;
			status =
				g_plugin_handlers.gdtr_idtr_access_event_handler(
					vcpu_id, dtr_access_data->qualification,
					dtr_access_data->instruction_info);
		}
		break;
	case MON_EVENT_MSR_READ_ACCESS:
		if (!g_plugin_handlers.msr_read_event_handler) {
			status = TRUE;
		} else {
			status = g_plugin_handlers.msr_read_event_handler(
				vcpu_id);
		}
		break;
	case MON_EVENT_MSR_WRITE_ACCESS:
		msr_write_access_data =
			(report_msr_write_access_data_t *)event_specific_data;
		status = msr_write_handler(gcpu,
			(msr_id_t)msr_write_access_data->msr_id,
			&msr_value);
		break;
	case MON_EVENT_SET_ACTIVE_EPTP:
		if (!g_plugin_handlers.fvs_set_active_view_event_handler) {
			status = TRUE;
		} else {
			set_active_eptp_data =
				(report_set_active_eptp_data_t *)
				event_specific_data;
			status =
				g_plugin_handlers.
				fvs_set_active_view_event_handler(
					vcpu_id,
					set_active_eptp_data->eptp_list_index,
					set_active_eptp_data->update_hw);
		}
		break;
	case MON_EVENT_INITIAL_VMEXIT_CHECK:
		if (!g_plugin_handlers.initial_vmexit_check_event_handler) {
			status = FALSE;
		} else {
			/* NOTE: gcpu cache and vmcs cache is not cleared at this point.
			 *       Any reads/writes to VMCS will go directly to the
			 *       hardware. */
			initial_vmexit_check_data =
				(report_initial_vmexit_check_data_t *)
				event_specific_data;
			status =
				g_plugin_handlers.
				initial_vmexit_check_event_handler(
					vcpu_id,
					initial_vmexit_check_data->current_cpu_rip,
					initial_vmexit_check_data->vmexit_reason);
		}
		break;
	case MON_EVENT_SINGLE_STEPPING_CHECK:
		if (!g_plugin_handlers.single_stepping_check_event_handler) {
			status = TRUE;
		} else {
			status =
				g_plugin_handlers.
				single_stepping_check_event_handler(
					vcpu_id);
		}
		break;
	case MON_EVENT_MON_TEARDOWN:
		if (!g_plugin_handlers.mon_teardown_event_handler) {
			status = TRUE;
		} else {
			mon_teardown_data =
				(report_mon_teardown_data_t *)
				event_specific_data;
			status = g_plugin_handlers.mon_teardown_event_handler(
				vcpu_id, mon_teardown_data->nonce);
		}
		break;
	case MON_EVENT_INVALID_FAST_VIEW_SWITCH:
		if (!g_plugin_handlers.invalid_fvs_event_handler) {
			status = TRUE;
		} else {
			fast_view_switch_data =
				(report_fast_view_switch_data_t *)
				event_specific_data;
			status = g_plugin_handlers.invalid_fvs_event_handler(
				vcpu_id, fast_view_switch_data->reg);
		}
		break;
	case MON_EVENT_VMX_PREEMPTION_TIMER:
		if (!g_plugin_handlers.vmx_preemption_timer_event_handler) {
			status = TRUE;
		} else {
			status =
				g_plugin_handlers.
				vmx_preemption_timer_event_handler(
					vcpu_id);
		}
		break;
	case MON_EVENT_HALT_INSTRUCTION:
		if (!g_plugin_handlers.halt_instruction_event_handler) {
			status = TRUE;
		} else {
			status =
				g_plugin_handlers.halt_instruction_event_handler(
					vcpu_id);
		}
		break;
	case MON_EVENT_NMI:
		if (!g_plugin_handlers.build_nmi_event_handler) {
			status = TRUE;
		} else {
			status = g_plugin_handlers.build_nmi_event_handler(
				vcpu_id);
		}
		break;
	case MON_EVENT_LOG:
		if (g_plugin_handlers.log_event_handler) {
			mon_log_event_data =
				(report_mon_log_event_data_t *)
				event_specific_data;
			g_plugin_handlers.log_event_handler(vcpu_id,
				mon_log_event_data->vector);
		}
		status = TRUE;
		break;
	case MON_EVENT_UPDATE_ACTIVE_VIEW:
		xmon_update_active_view(gcpu);
		status = TRUE;
		break;
	case MON_EVENT_MON_ASSERT:
		if (g_plugin_handlers.mon_assert_event_handler) {
			/* Switch to the view Plugin specified by updating
			 * VMCS_EPTP_ADDRESS field */
			xmon_update_vmcs_eptp_address(
				gcpu,
				g_plugin_handlers.mon_assert_event_handler(
					vcpu_id));
		}
		status = TRUE;
		break;
	case MON_EVENT_CPUID:
		if (!g_plugin_handlers.cpuid_vmexit_event_handler) {
			status = FALSE;
		} else {
			cpuid_data = (report_cpuid_data_t *)event_specific_data;
			status = g_plugin_handlers.cpuid_vmexit_event_handler(
				vcpu_id, cpuid_data->params);
		}
		break;
	}

	return status;
}

boolean_t xmon_hva_to_hpa(hva_t hva, hpa_t *hpa)
{
	return mon_hmm_hva_to_hpa(hva, hpa);
}

boolean_t xmon_hpa_to_hva(hpa_t hpa, hva_t *hva)
{
	return mon_hmm_hpa_to_hva(hpa, hva);
}

boolean_t xmon_gva_to_gpa(const guest_vcpu_t *vcpu_id, gva_t gva, gpa_t *gpa)
{
	return mon_gcpu_gva_to_gpa(get_gcpu_from_guest_vcpu(
			vcpu_id), gva, 0, gpa);
}

boolean_t xmon_gva_to_gpa_from_cr3(const guest_vcpu_t *vcpu_id, gva_t gva,
				   uint64_t cr3, gpa_t *gpa)
{
	return mon_gcpu_gva_to_gpa(get_gcpu_from_guest_vcpu(
			vcpu_id), gva, cr3, gpa);
}

boolean_t xmon_inject_exception(const guest_vcpu_t *vcpu_id,
				exception_type_t exception_type)
{
	boolean_t status = FALSE;

	switch (exception_type) {
	case EXCEPTION_TYPE_UD:
		status = mon_gcpu_inject_invalid_opcode_exception(
			get_gcpu_from_guest_vcpu(vcpu_id));
		break;
	case EXCEPTION_TYPE_GP:
		status = mon_gcpu_inject_gp0(get_gcpu_from_guest_vcpu(vcpu_id));
		break;
	default:
		MON_LOG(mask_xmon_api,
			level_error,
			"%s: Invalid exception type %d\n",
			__FUNCTION__,
			exception_type);
		MON_DEADLOOP();
		return FALSE;
	}

	if (!status) {
		MON_LOG(mask_xmon_api, level_error,
			"%s: Failed to inject exception %d\n",
			__FUNCTION__, exception_type);
	}

	return status;
}

boolean_t xmon_is_unrestricted_guest_supported(void)
{
	return mon_is_unrestricted_guest_supported();
}

uint64_t xmon_get_cr0_minimal_settings(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return gcpu->vmexit_setup.cr0.minimal_1_settings;
}

uint64_t xmon_get_cr4_minimal_settings(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return gcpu->vmexit_setup.cr4.minimal_1_settings;
}

boolean_t xmon_get_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
				    mon_guest_state_t guest_state_id,
				    mon_guest_state_value_t *value)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);

	return mon_get_vmcs_guest_state(gcpu, guest_state_id, value);
}

boolean_t xmon_set_vmcs_guest_state(const guest_vcpu_t *vcpu_id,
				    mon_guest_state_t guest_state_id,
				    mon_guest_state_value_t value)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);

	return mon_set_vmcs_guest_state(gcpu, guest_state_id, value);
}

boolean_t xmon_get_vmcs_control_state(const guest_vcpu_t *vcpu_id,
				      mon_control_state_t control_state_id,
				      mon_controls_t *value)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);

	return mon_get_vmcs_control_state(gcpu, control_state_id, value);
}

boolean_t xmon_set_vmcs_control_state(const guest_vcpu_t *vcpu_id,
				      mon_control_state_t control_state_id,
				      mon_controls_t *value)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);

	return mon_set_vmcs_control_state(gcpu, control_state_id, value);
}

const guest_vcpu_t *xmon_get_guest_vcpu(void)
{
	guest_cpu_handle_t gcpu = mon_scheduler_current_gcpu();

	MON_ASSERT(gcpu);
	return get_guest_vcpu_from_gcpu(gcpu);
}

/*
 * XMON API Utility Functions
 */
const guest_vcpu_t *get_guest_vcpu_from_gcpu(const guest_cpu_handle_t gcpu)
{
	return (const guest_vcpu_t *)mon_guest_vcpu(gcpu);
}

guest_cpu_handle_t get_gcpu_from_guest_vcpu(const guest_vcpu_t *vcpu_id)
{
	MON_ASSERT(vcpu_id);
	MON_ASSERT(vcpu_id->guest_cpu_id < g_xmon_num_of_cpus);
	MON_ASSERT(g_xmon_cpu_state);
	MON_ASSERT(vcpu_id == g_xmon_cpu_state[vcpu_id->guest_cpu_id]->vcpu_id);
	return (guest_cpu_handle_t)g_xmon_cpu_state[vcpu_id->guest_cpu_id]->gcpu;
}

/******************************************************************************
 * Function Name: set_xmon_state
 * Parameters: parameters gcpu and vcpu_id are assumed valid. Caller function
 * must validate.
 *******************************************************************************/
void set_xmon_state(guest_cpu_handle_t gcpu, const guest_vcpu_t *vcpu_id)
{
	MON_ASSERT(gcpu);
	MON_ASSERT(vcpu_id->guest_cpu_id < g_xmon_num_of_cpus);
	g_xmon_cpu_state[vcpu_id->guest_cpu_id]->gcpu =
		(mon_identification_data_t)gcpu;
	g_xmon_cpu_state[vcpu_id->guest_cpu_id]->vcpu_id = vcpu_id;
}

boolean_t xmon_get_vmexit_reason(const guest_vcpu_t *vcpu_id,
				 vmexit_reason_t *reason)
{
	guest_cpu_handle_t gcpu = NULL;
	vmcs_object_t *vmcs = NULL;

	gcpu = get_gcpu_from_guest_vcpu(vcpu_id);
	MON_ASSERT(gcpu);

	vmcs = mon_gcpu_get_vmcs(gcpu);
	reason->reason = mon_vmcs_read(vmcs, VMCS_EXIT_INFO_REASON);
	reason->qualification =
		mon_vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
	reason->gva = mon_vmcs_read(vmcs, VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS);

	return TRUE;
}
