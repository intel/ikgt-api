################################################################################
# Copyright (c) 2015 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

$(shell mkdir -p $(OUTDIR)api/)

TARGET = libapi.a

CSOURCES = $(wildcard *.c)

INCLUDES = -I. \
           -I$(PROJS)/common/include \
           -I./include \
           -I$(PLUGIN_DIR)/wrapper \
           -I$(PLUGIN_DIR)/wrapper/include \
           -I$(PROJS)/core/common/include \
           -I$(PROJS)/core/common/include/arch \
           -I$(PROJS)/core/include \
           -I$(PROJS)/core/include/hw \
           -I$(PROJS)/core/guest \
           -I$(PROJS)/core/guest/guest_cpu \
           -I$(PROJS)/core/memory/ept

CFLAGS = -c $(XMON_CMPL_OPT_FLAGS) \
         -O2 -std=gnu99 -fPIC -nostdinc -fno-stack-protector \
         -fdiagnostics-show-option -funsigned-bitfields \
         -m64 -march=nocona -D ARCH_ADDRESS_WIDTH=8 \
         -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-3dnow \
         -fno-hosted -fomit-frame-pointer

CFLAGS += $(INCLUDES)


COBJS = $(addprefix $(OUTDIR)api/, $(notdir $(patsubst %.c, %.o, $(CSOURCES))))


all: $(COBJS) $(TARGET)

$(COBJS): $(CSOURCES)
	$(CC) $(CFLAGS) -o $@ $(filter $(*F).c, $(CSOURCES))

$(TARGET):
	$(AR) rcs $(BINDIR)$@ $(wildcard $(OUTDIR)api/*.o)
