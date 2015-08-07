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
#define MON_DEADLOOP()          MON_DEADLOOP_LOG(XMON_VE_C)
#define MON_ASSERT(__condition) MON_ASSERT_LOG(XMON_VE_C, __condition)
#include "xmon_internal.h"
#include "guest_cpu.h"
#include "guest.h"

boolean_t xmon_is_hw_ve_supported()
{
	return mon_ve_is_hw_supported();
}

boolean_t xmon_is_ve_enabled(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return mon_ve_is_ve_enabled(gcpu);
}

boolean_t xmon_ve_update_hpa(guest_id_t guest_id, cpu_id_t guest_cpu_id,
			     hpa_t hpa, uint32_t enable)
{
	return mon_ve_update_hpa(guest_id, guest_cpu_id, hpa, enable);
}

void xmon_ve_enable(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	mon_ve_enable_ve(gcpu);
}

void xmon_ve_disable(const guest_vcpu_t *vcpu_id)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	mon_ve_disable_ve(gcpu);
}

boolean_t xmon_handle_sw_ve(const guest_vcpu_t *vcpu_id, uint64_t qualification,
			    uint64_t gla, uint64_t gpa, uint64_t view)
{
	guest_cpu_handle_t gcpu = get_gcpu_from_guest_vcpu(vcpu_id);

	MON_ASSERT(gcpu);
	return mon_ve_handle_sw_ve(gcpu, qualification, gla, gpa, view);
}
