#include <pcap.h>
#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define RAISE(msg) \
	{PyErr_SetString(PyExc_Exception,msg); return NULL;}

PyObject* open_live(PyObject *self, PyObject *args) {
    int snaplen;//the maximum number of bytes to capture
    int promisc;//whether the interface is to be put into promiscuous mode
    int to_ms;//the read timeout in milliseconds
    char errbuf[PCAP_ERRBUF_SIZE];//error buffer
    const char *device;//interface to open
    pcap_t *handler;
    
    if (!PyArg_ParseTuple(args, "siii", &device,
            &snaplen, &promisc, &to_ms))
		RAISE("argument error!")
	
    handler = pcap_open_live(device, snaplen, promisc,
                to_ms, errbuf);
    if(handler == NULL)
        RAISE(errbuf)
    
    return Py_BuildValue("i", handler);
}

PyObject* lclose(PyObject *self, PyObject *args) {
    pcap_t *p;
    
    if (!PyArg_ParseTuple(args, "i", &p))
        RAISE("argument error!")
    
    pcap_close(p);
    
    Py_RETURN_NONE;
}

PyObject* geterr(PyObject *self, PyObject *args) {
    pcap_t *p;
    
    if (!PyArg_ParseTuple(args, "i", &p))
        RAISE("argument error!")
    
    return Py_BuildValue("s", pcap_geterr(p));
}

PyObject* sendpacket(PyObject *self, PyObject *args) {
    pcap_t *p;
    PyObject *str;
    
    if (!PyArg_ParseTuple(args, "iO", &p, &str))
        RAISE("argument error!")
    if (!PyBytes_Check(str))
        RAISE("packet must be a bytes")
    if (pcap_sendpacket(p, PyBytes_AsString(str), PyBytes_Size(str)))
        RAISE(pcap_geterr(p))
    
    Py_RETURN_NONE;
}

PyObject* readpacket(PyObject *self, PyObject *args) {
    pcap_t *p;
    struct pcap_pkthdr h;
    u_char *packet;
    PyObject *data;
    
    if (!PyArg_ParseTuple(args, "i", &p))
        RAISE("argument error!")
    
    Py_BEGIN_ALLOW_THREADS
    packet = pcap_next(p, &h);
    Py_END_ALLOW_THREADS
    if(packet == NULL)
        RAISE(pcap_geterr(p))
    
    data = PyBytes_FromStringAndSize(packet, h.len);
    if(data == NULL)
        RAISE("bild packet failure!")
    
    return Py_BuildValue("(O,{s:i,s:i})",
                data,
                "sec", h.ts.tv_sec, "usec", h.ts.tv_usec
                );
}

PyObject* filter(PyObject *self, PyObject *args) {
    pcap_t *p;
    struct bpf_program *fp;
    const char *str;
    int optimize;
    u_int netmask;
    
    if (!PyArg_ParseTuple(args, "isii", &p, &str, &optimize, &netmask))
        RAISE("argument error!")
    fp = (struct bpf_program*)malloc(sizeof(struct bpf_program));
    
    if(pcap_compile(p, fp, str, optimize, netmask))
        RAISE(pcap_geterr(p))
    
    if(pcap_setfilter(p, fp))
        RAISE(pcap_geterr(p))
    
    return Py_BuildValue("i", fp);
}

PyObject* freecode(PyObject *self, PyObject *args) {
    struct bpf_program *fp;
    
    if (!PyArg_ParseTuple(args, "i", &fp))
        RAISE("argument error!")
    pcap_freecode(fp);
    
    Py_RETURN_NONE;
}

PyObject *getaddr(PyObject *self, PyObject *args) {
    char *device;
    unsigned char macaddr[6];
    int s = socket(AF_INET,SOCK_DGRAM,0);
    struct ifreq req;
    int ip;
    
    if (!PyArg_ParseTuple(args, "s", &device))
        RAISE("argument error!")
    
    strcpy(req.ifr_name, device);
    if(ioctl(s,SIOCGIFHWADDR,&req))
        RAISE(strerror(errno))
    memcpy(macaddr, req.ifr_hwaddr.sa_data, 6);
    
    if (ioctl(s, SIOCGIFADDR, &req))
        RAISE(strerror(errno))
    ip = ((struct sockaddr_in*)&(req.ifr_addr))->sin_addr.s_addr;
    
    close(s);
    
    return Py_BuildValue("(i,O)", ip,
                PyBytes_FromStringAndSize(macaddr, 6));
}

static PyMethodDef LoCPcapMethods[] = {                  
    {"open", open_live, METH_VARARGS, "pcap_open_live"},
    {"close", lclose, METH_VARARGS, "pcap_close"},
    {"geterr", geterr, METH_VARARGS, "pcap_geterr"},
    {"send", sendpacket, METH_VARARGS, "pcap_sendpacket"},
    {"read", readpacket, METH_VARARGS, "pcap_next"},
    {"filter", filter, METH_VARARGS, "pcap_setfilter"},
    {"freecode", freecode, METH_VARARGS, "pcap_freecode"},
    {"getaddr", getaddr, METH_VARARGS, "get interface's address"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
   PyModuleDef_HEAD_INIT,
   "locpcap", "doc", -1, LoCPcapMethods
};

PyMODINIT_FUNC PyInit_locpcap(void) {
    PyObject *m;

    m = PyModule_Create(&module);
    if (m == NULL)
        return NULL;

    return m;
}
