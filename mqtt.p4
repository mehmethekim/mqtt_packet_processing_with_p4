/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<320> ALARM_TOPIC = 0x666163746f72792f616c61726d0d0a; //18 byte Topic = ROOM/TEMP
const bit<32> TEMP_THRESHOLD = 25;
const bit<32> CLOUD_BROKER_IP = 0x0A000404; //10.0.4.4
const bit<32> EDGE_BROKER_IP = 0x0A000303; //10.0.3.3

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}
header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}
header Tcp_option_ts_h{
    bit <8> kind;
    bit <8> len;
    bit<64> ts; // Now it is 10 bytes of length after it.
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}
header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_ts_h   ts;
    Tcp_option_sack_h sack;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

/* header for mqtt publish message
Publish acknowledge and connect header have different lengths and headers.

*/
header mqtt_fixed_t{ 
    bit<4> message_type; //0x03 publish
    bit<1> dup_flag;      //0
    bit<2> qos_lvl; //0
    bit<1> retain; // 0
    bit<8> remaining_len; //remaining length of the message; Remaning number of BYTES. 2^8 byte is 2^3 * 2^8
    bit<16> topic_len; //Topic length

}
header mqtt_topic_t{
    varbit<1000> topic; // length is topic_len
   
}
header mqtt_payload_t{
    varbit<8096> payload; //length is (remaining_len - topic_len)
}
 

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    Tcp_option_stack tcp_options_vec;
    mqtt_fixed_t      mqtt_fixed;
    mqtt_topic_t   mqtt_topic;
    mqtt_payload_t   mqtt_payload;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser Tcp_option_parser(packet_in b, out Tcp_option_stack vec) {
    state start {
        transition select(b.lookahead<bit<8>>()) {
            8w0x0 : parse_tcp_option_end;
            8w0x1 : parse_tcp_option_nop;
            8w0x2 : parse_tcp_option_ss;
            8w0x3 : parse_tcp_option_s;
            8w0x5 : parse_tcp_option_sack;
            8w0x8 : parse_tcp_option_ts;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        transition accept;
    }
    state parse_tcp_option_nop {
         b.extract(vec.next.nop);
         transition start;
    }
    state parse_tcp_option_ts{
        b.extract(vec.next.ts);
        transition accept;
    }
    state parse_tcp_option_ss {
         b.extract(vec.next.ss);
         transition start;
    }
    state parse_tcp_option_s {
         b.extract(vec.next.s);
         transition start;
    }
    state parse_tcp_option_sack {
         bit<8> n = b.lookahead<Tcp_option_sack_top>().length;
         // n is the total length of the TCP SACK option in bytes.
         // The length of the varbit field 'sack' of the
         // Tcp_option_sack_h header is thus n-2 bytes.
        
        b.extract(vec.next.sack, (bit<32>) (8 * n - 16));  
         transition start;
    }
}
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    //Start parsing ethernet packet
    state start {
        transition parse_ethernet;
    }
    //Extract ethernet packet, if it is has an IP packet, go to IPv4 parsing
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    //Parse IPv4 and go on with parsing TCP
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }
    //go to TCP option parser
    state parse_tcp {
        packet.extract(hdr.tcp);
        Tcp_option_parser.apply(packet,hdr.tcp_options_vec);
        transition parse_mqtt_fixed;
    }
    state parse_mqtt_fixed{
        packet.extract(hdr.mqtt_fixed);
        transition parse_mqtt_topic;
    }
    state parse_mqtt_topic{
        packet.extract(hdr.mqtt_topic,(bit<32>)(8*hdr.mqtt_fixed.topic_len)); //For example, topic len of three will be three bytes = 24 bit for the topic.
        transition parse_mqtt_payload;
    }
    state parse_mqtt_payload{
        packet.extract(hdr.mqtt_payload,(bit<32>)(8*( (bit<16>)hdr.mqtt_fixed.remaining_len-hdr.mqtt_fixed.topic_len)));
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if(hdr.ipv4.isValid()){
            if (hdr.mqtt_fixed.isValid()){ 
                //varbit<1000>temp_topic = hdr.mqtt_topic.topic; 
                //&& temp_topic == ALARM_TOPIC
                if(hdr.ipv4.dstAddr == CLOUD_BROKER_IP && hdr.mqtt_fixed.message_type == 0x03){
                    hdr.ipv4.dstAddr = EDGE_BROKER_IP;//change destination src to EDGEBROKER
                }
            //If it is not an alarm topic, check if it exceeds the threshold,
                ipv4_lpm.apply();

            // if(hdr.mqtt_topic.topic != ALARM_TOPIC){
            //     if(hdr.mqtt_payload.payload>TEMP_THRESHOLD){
            //         //Update mqtt packet headers, update remaining length and topic length.
            //         //hdr.mqtt_fixed.remaining_len = (hdr.mqtt_fixed.remaining_len-hdr.mqtt_fixed.topic_len+30);
            //         //hdr.mqtt_fixed.topic_len = 30;
            //         //hdr.mqtt_topic.topic = ALARM_TOPIC;//If it is exceeds threshold, chenage its topic to ALARM
            //         //forward a copy to cloud broker.
            //         //then change address and forward again.
            //         // hdr.ipv4.dstAddr = EDGE_BROKER_IP;//change destination src to EDGEBROKER
                    
            //     }
                
            //     //forward the message It will redirect the message to h2.
            // }
            //If it is an alarm topic , check where it comes. If it comes from the cloud, it is the coppied message, if it comes from edge broker, it is the original changed message
            
            }
            else{
                ipv4_lpm.apply();
            }
        }
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_vec);
        packet.emit(hdr.mqtt_fixed);
        packet.emit(hdr.mqtt_topic);
        packet.emit(hdr.mqtt_payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
