MAINTAINERCLEANFILES = Makefile.in

SUBDIRS=interfaces openflow system virtualization-agent

noinst_LTLIBRARIES = libxdpd_mgmt_config.la

libxdpd_mgmt_config_la_SOURCES = \
	scope.cc \
	root_scope.cc \
	config.cc 

libxdpd_mgmt_config_la_LIBADD = \
	interfaces/libxdpd_mgmt_config_interfaces.la\
	openflow/libxdpd_mgmt_config_openflow.la\
	system/libxdpd_mgmt_config_system.la\
	virtualization-agent/libxdpd_mgmt_config_virtualization_agent.la\
	-lconfig++
