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

#ifndef _XMON_INTERNAL_H
#define _XMON_INTERNAL_H

#include "xmon_api.h"
#include "memory_address_mapper_api.h"
#include "ept.h"
#include "scheduler.h"
#include "ipc.h"

/* Should be same as number of elements in xmon_msrs_monitored */
#define PLUGIN_MAX_MON_HANDLED_MSRS 54

typedef struct {
	gpm_handle_t	gpm;
	mam_handle_t	address_space;
	uint64_t	ept_root_table_hpa;
	uint32_t	gaw;
	char		padding[4];
} guest_view_t;

typedef struct {
	mon_identification_data_t	gcpu;
	const guest_vcpu_t		*vcpu_id;
} xmon_cpu_state_t;

extern xmon_event_handlers_t g_plugin_handlers;

const guest_vcpu_t *get_guest_vcpu_from_gcpu(const guest_cpu_handle_t gcpu);
guest_cpu_handle_t get_gcpu_from_guest_vcpu(const guest_vcpu_t *vcpu_id);
void set_xmon_state(guest_cpu_handle_t gcpu, const guest_vcpu_t *vcpu_id);

boolean_t msr_write_handler(guest_cpu_handle_t gcpu,
			    msr_id_t msr_id,
			    uint64_t *msr_value);
void xmon_update_vmcs_eptp_address(guest_cpu_handle_t gcpu,
				   uint64_t eptp_list_index);
void xmon_update_active_view(guest_cpu_handle_t gcpu);
#endif /*_XMON_INTERNAL_H */
