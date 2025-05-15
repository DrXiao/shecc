# Check the prerequisites
PREREQ_LIST := dot jq $(ARCH_EXEC)
PREREQ_EXEC := $(shell which $(PREREQ_LIST))
PREREQ_MISSING := $(filter-out $(notdir $(PREREQ_EXEC)),$(PREREQ_LIST))

ifdef PREREQ_MISSING
$(warning "Necessary packages: $(PREREQ_LIST)")
$(warning "Missing packages: $(PREREQ_MISSING)")
$(error "Please check package installation")
endif
