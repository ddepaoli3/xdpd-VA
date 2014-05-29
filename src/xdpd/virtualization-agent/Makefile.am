MAINTAINERCLEANFILES = Makefile.in


noinst_LTLIBRARIES = libvirtualization_agent.la

libvirtualization_agent_la_SOURCES = \
	virtualagent.cc \
	virtualagent.h \
	slice.h \
	slice.cc \
	virtualgateway.h \
	virtualgateway.cc \
	flowspace.h \
	va_switch.cc \
	va_switch.h

libvirtualization_agent_la_LIBADD = \
	../management/libxdpd_mgmt.la \
	../openflow/libxdpd_openflow.la \
	../openflow/openflow12/libxdpd_openflow12.la
