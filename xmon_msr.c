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
#define MON_DEADLOOP()          MON_DEADLOOP_LOG(XMON_MSR_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(XMON_MSR_C, __condition)
#include "xmon_internal.h"
#include "guest_cpu.h"
#include "guest.h"
#include "vmx_ctrl_msrs.h"
#include "mtrrs_abstraction.h"

/*
 * These are the MSRs handled by MON irrespective of whether Msr Write
 * monitoring is enabled. PLUGIN_MAX_MON_HANDLED_MSRS should be changed
 * if any MSR is added/removed
 */
static msr_id_t xmon_msrs_monitored[] = {
	IA32_MSR_VMX_BASIC_INDEX,
	IA32_MSR_PIN_BASED_VM_EXECUTION_CONTROLS_INDEX,
	IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX,
	IA32_MSR_PROCESSOR_BASED_VM_EXECUTION_CONTROLS2_INDEX,
	IA32_MSR_VM_EXIT_CONTROLS_INDEX,
	IA32_MSR_VM_ENTRY_CONTROLS_INDEX,
	IA32_MSR_MISCELLANEOUS_DATA_INDEX,
	IA32_MSR_CR0_ALLOWED_ZERO_INDEX,
	IA32_MSR_CR0_ALLOWED_ONE_INDEX,
	IA32_MSR_CR4_ALLOWED_ZERO_INDEX,
	IA32_MSR_CR4_ALLOWED_ONE_INDEX,
	IA32_MSR_VMX_VMCS_ENUM,
	IA32_MSR_EPT_VPID_CAP_INDEX,
	IA32_MSR_TRUE_PINBASED_CTLS_INDEX,
	IA32_MSR_TRUE_PROCBASED_CTLS_INDEX,
	IA32_MSR_TRUE_EXIT_CTLS_INDEX,
	IA32_MSR_TRUE_ENTRY_CTLS_INDEX,
	IA32_MSR_VMX_VMFUNC_CTRL,
	IA32_MSR_EFER,
	IA32_MSR_APIC_BASE,
	IA32_MSR_FEATURE_CONTROL,
	IA32_MSR_MTRRCAP,
	IA32_MSR_MTRR_DEF_TYPE,
	IA32_MSR_FIXED_MTRR_64K_00000,
	IA32_MSR_FIXED_MTRR_16K_80000,
	IA32_MSR_FIXED_MTRR_16K_A0000,
	IA32_MSR_FIXED_MTRR_4K_C0000,
	IA32_MSR_FIXED_MTRR_4K_C8000,
	IA32_MSR_FIXED_MTRR_4K_D0000,
	IA32_MSR_FIXED_MTRR_4K_D8000,
	IA32_MSR_FIXED_MTRR_4K_E0000,
	IA32_MSR_FIXED_MTRR_4K_E8000,
	IA32_MSR_FIXED_MTRR_4K_F0000,
	IA32_MSR_FIXED_MTRR_4K_F8000,
	IA32_MTRR_PHYSMASK0_ADDR,
	IA32_MTRR_PHYSBASE1_ADDR,
	IA32_MTRR_PHYSMASK1_ADDR,
	IA32_MTRR_PHYSBASE2_ADDR,
	IA32_MTRR_PHYSMASK2_ADDR,
	IA32_MTRR_PHYSBASE3_ADDR,
	IA32_MTRR_PHYSMASK3_ADDR,
	IA32_MTRR_PHYSBASE4_ADDR,
	IA32_MTRR_PHYSMASK4_ADDR,
	IA32_MTRR_PHYSBASE5_ADDR,
	IA32_MTRR_PHYSMASK5_ADDR,
	IA32_MTRR_PHYSBASE6_ADDR,
	IA32_MTRR_PHYSMASK6_ADDR,
	IA32_MTRR_PHYSBASE7_ADDR,
	IA32_MTRR_PHYSMASK7_ADDR,
	IA32_MTRR_PHYSBASE8_ADDR,
	IA32_MTRR_PHYSMASK8_ADDR,
	IA32_MTRR_PHYSBASE9_ADDR,
	IA32_MTRR_PHYSMASK9_ADDR,
	IA32_MSR_MISC_ENABLE
};

#define VHM_W_BIT ((uint32_t)0x2)

uint32_t g_msr_monitored_by_plugin[PLUGIN_MAX_MON_HANDLED_MSRS];

/* Macro input "idx" is index to arrays above, not the MSR ID. */
#define VHM_SET_W_BIT(idx) (g_msr_monitored_by_plugin[idx] |= VHM_W_BIT)
#define VHM_CLR_W_BIT(idx) (g_msr_monitored_by_plugin[idx] &= ~VHM_W_BIT)
#define VHM_GET_W_BIT(idx) (g_msr_monitored_by_plugin[idx] & VHM_W_BIT)

static
uint32_t xmon_get_index_from_msr_id(msr_id_t msr_id)
{
	uint32_t i;

	for (i = 0; i < NELEMENTS(xmon_msrs_monitored); i++)
		if (xmon_msrs_monitored[i] == msr_id) {
			break;
		}

	return i;
}

boolean_t msr_write_handler(guest_cpu_handle_t gcpu,
			    msr_id_t msr_id,
			    uint64_t *msr_value)
{
	boolean_t response = FALSE, mon_handled = FALSE;
	const guest_vcpu_t *vcpu_id = NULL;
	uint32_t i = 0;

	i = xmon_get_index_from_msr_id(msr_id);

	/* Check if this is an MSR handled by core MON and if so,
	 * was monitoring enabled for it? */
	if (i < NELEMENTS(xmon_msrs_monitored)) { /* handled by MON */
		mon_handled = TRUE;
		if (VHM_GET_W_BIT(i) == 0) {
			return TRUE; /* plugin not monitored */
		}
	}

	MON_ASSERT(gcpu);
	vcpu_id = get_guest_vcpu_from_gcpu(gcpu);
	if (!vcpu_id) {
		return FALSE;
	}
	set_xmon_state(gcpu, vcpu_id);

	if (!g_plugin_handlers.msr_write_event_handler) {
		return FALSE;
	}

	/* Report to Handler, enable MTF for EFER and PAT */
	response = g_plugin_handlers.msr_write_event_handler(vcpu_id, msr_id,
		mon_handled);

	/* IB Dispatch has been set up for MSR monitored by plugin only.
	 * Do not update register. Or specified exception needs to be injected */
	if (FALSE == response) {
		return FALSE;
	}

	/* MON not handled but plugin monitored */
	if (FALSE == mon_handled) {
		mon_gcpu_set_msr_reg_by_index(gcpu, msr_id, *msr_value);
	}

	return TRUE;
}

msr_reg_status_t xmon_register_msr_write(const guest_vcpu_t *vcpu_id,
					 msr_id_t msr_id)
{
	uint32_t j = 0;
	mon_status_t status = MON_OK;
	guest_handle_t guest;

	MON_ASSERT(vcpu_id);
	guest = mon_guest_handle(vcpu_id->guest_id);

	if (((msr_id > MSR_LOW_LAST) && (msr_id < MSR_HIGH_FIRST))
	    || ((msr_id > MSR_HIGH_LAST))) {
		MON_LOG(mask_xmon_api,
			level_error,
			"CPU%d: %s: Error: Invalid MsrId - 0x%X - Not in range.\n",
			vcpu_id->guest_cpu_id,
			__FUNCTION__,
			(uint32_t)msr_id);
		return MSR_ID_INVALID;
	}

	/* Convert msr_id to the index of array of mon handled msrs */
	j = xmon_get_index_from_msr_id(msr_id);

	/* For msr EFER, needs to register/unregister with its special
	 * mon handler */
	if (IA32_MSR_EFER == msr_id) {
		MON_ASSERT(j < NELEMENTS(xmon_msrs_monitored));
		if (!VHM_GET_W_BIT(j)) { /* not registered */
			if (TRUE ==
			    mon_vmexit_register_unregister_for_efer(guest,
				    msr_id,
				    WRITE_ACCESS, TRUE)) {
				/* register successfully */
				VHM_SET_W_BIT(j);
			} else { /* register fail */
				return MSR_REG_FAIL;
			}
		}
		return MSR_REG_OK; /* already registered, returns OK */
	}

	/* For other MSRs handled by MON */
	if (j < NELEMENTS(xmon_msrs_monitored)) {
		/* Check for unsupported MSR's on older processors */
		if (!mon_mtrrs_is_variable_mtrrr_supported((uint32_t)msr_id)) {
			MON_LOG(mask_xmon_api,
				level_error,
				"CPU%d: %s: Error: Invalid MsrId - 0x%X - Not supported"
				"on this processor.\n",
				vcpu_id->guest_cpu_id,
				__FUNCTION__,
				(uint32_t)msr_id);
			return MSR_ID_INVALID;
		}
		VHM_SET_W_BIT(j);
		return MSR_REG_OK;
	}

	/* For MSRs not handled by MON */
	status = mon_msr_vmexit_handler_register(
		guest,
		msr_id,
		(msr_access_handler_t)msr_write_handler,
		WRITE_ACCESS,
		NULL);

	if (MON_ERROR == status) {
		MON_LOG(mask_xmon_api,
			level_error,
			"CPU%d: %s: Error: Could not register MSR 0x%X for write"
			" handler.\n",
			vcpu_id->guest_cpu_id,
			__FUNCTION__,
			(uint32_t)msr_id);
		return MSR_REG_FAIL;
	}

	return MSR_REG_OK;
}

boolean_t xmon_unregister_msr_write(const guest_vcpu_t *vcpu_id,
				    msr_id_t msr_id)
{
	uint32_t j = 0;
	mon_status_t status = MON_OK;
	guest_handle_t guest;

	MON_ASSERT(vcpu_id);
	guest = mon_guest_handle(vcpu_id->guest_id);

	j = xmon_get_index_from_msr_id(msr_id);

	/* For EFER, unregister it by its own unregister function */
	if (IA32_MSR_EFER == msr_id) {
		MON_ASSERT(j < NELEMENTS(xmon_msrs_monitored));
		if (VHM_GET_W_BIT(j)) {
			/* registered EFER, do unregister */
			mon_vmexit_register_unregister_for_efer(guest, msr_id,
				WRITE_ACCESS, FALSE);
			VHM_CLR_W_BIT(j);
		}
		/* Unregister successfully or not registered before */
		return TRUE;
	}

	/* For other MSRs handled by MON */
	if (j < NELEMENTS(xmon_msrs_monitored)) {
		/* Check for unsupported MSR's on older processors */
		if (!mon_mtrrs_is_variable_mtrrr_supported((uint32_t)msr_id)) {
			MON_LOG(mask_xmon_api,
				level_error,
				"CPU%d: %s: Error: Invalid MsrId - 0x%X - Not supported"
				"on this processor.\n",
				vcpu_id->guest_cpu_id,
				__FUNCTION__,
				(uint32_t)msr_id);
			return FALSE;
		}
		VHM_CLR_W_BIT(j);
		return TRUE;
	}

	/* For non-MON handled MSRs */
	status = msr_vmexit_handler_unregister(guest, msr_id, WRITE_ACCESS);

	if (MON_ERROR == status) {
		/* not registered valid msr_id */
		if ((msr_id <= MSR_LOW_LAST) || ((MSR_HIGH_FIRST <= msr_id) &&
						 (msr_id <= MSR_HIGH_LAST))) {
			return TRUE;
		} else {
			MON_LOG(mask_xmon_api,
				level_error,
				"CPU%d: %s: Error: Could not unregister MSR 0x%X for"
				" write handler.\n",
				vcpu_id->guest_cpu_id,
				__FUNCTION__,
				(uint32_t)msr_id);
			return FALSE;
		}
	}

	return TRUE;
}
