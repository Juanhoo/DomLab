import binascii

from scapy.all import *
from scapy.layers.l2 import Ether


class SocketCreator:

    def randomise_mac_address(self):
        mac = [0x30, 0x85, 0xa9,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),]

        result = []
        port_id = map(lambda y: "%02x" % y, mac)
        port_id = ":".join(port_id)

        chid = map(lambda y: "%02x" % y, mac)
        chid = "".join(chid)

        result.append(chid)
        result.append(port_id)
        return result



    def make_full_LLDP_packet(self, interface):
        full_packet_Data = {
            # Attribute 2 TLV = 1 and subtype = 4
            "ChTVL": "02",
            "ChSubtype": "04",
            "ChName": "0514bcbe30d5",
            # Attribute 3 TLV = 2 and subtype = 2
            "InterfTLV": "04",
            "InSub": "05",
            "MacAddress": "65746831",
            # Attribute 4 TLV = 3
            "TimeToLiveTLV": "06",
            "TimeToLive": "0030",
            # Attribute 5 TLV = 7
            "SysCapabTLV": "0e",
            "SysName": "0080",
            # Attribute 6 IPv4 TLV = 8
            "IpTLV": "10",
            "AddrStrLen": "05",
            "AddrSub": "01",
            "IpAddr": "c0a80109",  # 192.168.1.9
            "InterfSub": "02",
            "InterfNum": "00000005",
            "OIDLen": "00",
            # Attribute 7 TLV = 127 and subtype = 1
            "CipTLV": "fe",
            "org_code": "00216c",  # Odva
            "CipSubtype": "01",
            "venID": "0100",  # RA/A-B
            "DevType": "8f00",
            "Prod_code": "901f",
            "MjrRev": "0d",
            "MinRev": "01",
            "SerNumber": "994b5fd2",
            # Attribute 8 TLV = 127 subtype = 7
            "AdditEthTLV": "fe",
            "OUI": "00120f",  # Organizationally unique identifier
            "AdditSubtype": "07",
            "information": "Politechnika"
        }
        ip = self.randomise_mac_address()
        chid = ip[0]
        ipscr = ip[1]
        # TLV, uni_code, cip_subtype, vendor, device, prod_code, comp, revision, ser_numb
        # att1 = self.make_chasis_layer(tlv_id=full_packet_Data["ChTVL"], ch_Sub=full_packet_Data["ChSubtype"], chID_Str=binascii.hexlify(bytes(full_packet_Data["name"])))
        att2 = self.make_interf_Label(tlv_id=full_packet_Data["ChTVL"], ch_Sub=full_packet_Data["ChSubtype"],
                                      chID_Str=chid)
        att3 = self.make_chasis_layer(tlv_id=full_packet_Data["InterfTLV"], ch_Sub=full_packet_Data["InSub"],
                                      chID_Str=full_packet_Data["MacAddress"])
        # att31 = self.make_chasis_layer(tlv_id="01", ch_Sub="06", chID_Str=full_packet_Data["MacAddress"])
        att4 = self.make_ttl_layer(ttl_type=full_packet_Data["TimeToLiveTLV"],
                                   time_to_live=full_packet_Data["TimeToLive"])
        att5 = self.sys_capab_layer(sys_cap_ID=full_packet_Data["SysCapabTLV"], sys_cap=full_packet_Data["SysName"])
        att6 = self.management_address_Layer(tlv=full_packet_Data["IpTLV"], adr_len=full_packet_Data["AddrStrLen"],
                                             adr_sub=full_packet_Data["AddrSub"], ip=full_packet_Data["IpAddr"]
                                             , interf_sub=full_packet_Data["InterfSub"],
                                             intef_num=full_packet_Data["InterfNum"], OID=full_packet_Data["OIDLen"])
        att7 = self.cip_Id_layer(TLV=full_packet_Data["CipTLV"], uni_code=full_packet_Data["org_code"],
                                 cip_subtype=full_packet_Data["CipSubtype"]
                                 , vendor=full_packet_Data["venID"], device=full_packet_Data["DevType"],
                                 prod_code=full_packet_Data["Prod_code"],
                                 mjr_rev=full_packet_Data["MjrRev"], min_revision=full_packet_Data["MinRev"],
                                 ser_numb=full_packet_Data["SerNumber"])
        att8 = self.additional_eth_layer(AdditEthTLV=full_packet_Data["AdditEthTLV"], oui=full_packet_Data["OUI"],
                                         subtype=full_packet_Data["AdditSubtype"],
                                         data=(full_packet_Data["information"]))
        end = 0
        end_frame = struct.pack("H", end)
        frame = bytearray(binascii.b2a_hex(end_frame))

        payload = att2 + att3 + att4 + att5 + att6 + att7 + att8 + frame
        packet = (Ether(dst="01:80:c2:00:00:0e", src=ipscr, type=0x88cc) /
                  Raw(load=bytearray(binascii.a2b_hex(payload))))

        sendp(packet, iface=interface)

    def make_interf_Label(self, tlv_id, ch_Sub, chID_Str):
        _tlv_ID = binascii.a2b_hex(tlv_id)
        _ch_Sub = binascii.a2b_hex(ch_Sub)
        _ch_Id_Str = binascii.a2b_hex(chID_Str)
        _len = struct.pack(">B", (_ch_Id_Str.__len__() + _ch_Sub.__len__()))
        _path = _tlv_ID + _len + _ch_Sub + _ch_Id_Str
        return bytearray(binascii.b2a_hex(_path))

    def additional_eth_layer(self, AdditEthTLV, oui, subtype, data):
        _AdditEthTLV = binascii.a2b_hex(AdditEthTLV)
        _oui = binascii.a2b_hex(oui)
        _subtype = binascii.a2b_hex(subtype)

        var = bytearray(data.encode("ascii"))
        _data = binascii.hexlify((var))
        _len = struct.pack(">B", (_oui.__len__() + _subtype.__len__() + _data.__len__()))
        _path = _AdditEthTLV + _len + _oui + _subtype + _data
        return bytearray(binascii.b2a_hex(_path))

    def cip_Id_layer(self, TLV, uni_code, cip_subtype, vendor, device, prod_code, mjr_rev, min_revision, ser_numb):
        _tlv_ID = binascii.a2b_hex(TLV)
        _uni_code = binascii.a2b_hex(uni_code)
        _cip_subtype = binascii.a2b_hex(cip_subtype)
        _vendor = binascii.a2b_hex(vendor)
        _device = binascii.a2b_hex(device)
        _prod_code = binascii.a2b_hex(prod_code)
        _mjr_rev = binascii.a2b_hex(mjr_rev)
        _min_revision = binascii.a2b_hex(min_revision)
        _ser_numb = binascii.a2b_hex(ser_numb)
        _len = struct.pack(">B", (_uni_code.__len__() + _cip_subtype.__len__() + _vendor.__len__() +
                                  _device.__len__() + _prod_code.__len__() + _mjr_rev.__len__() + _min_revision.__len__() + _ser_numb.__len__()))
        _path = _tlv_ID + _len + _uni_code + _cip_subtype + _vendor + _device + _prod_code + _mjr_rev + _min_revision + _ser_numb
        return bytearray(binascii.b2a_hex(_path))

    def make_chasis_layer(self, tlv_id, ch_Sub, chID_Str):
        """
        Function returns chasis layer of the LLDP protocol

        Chasis layer consists of 4 parameters:
        Type(tlv_id): (1b) it should always be equal 1
        Length (1b) lengh of parameters 3 and 4, and it's size should be <= 34:
        Chasis ID Subtype (chSub) This parameter can take a value between 1 and 5:
         =1 -> set endPhysicalAlias for chassis
         =2 -> set ifAlias for an interface
         =3 -> set entPhysicalAlias for port or backplane
         =4 -> MAC address for the system
         =5 -> A management address for the system
        Chasis ID String(chIDStr)
        """
        _tlv_ID = binascii.a2b_hex(tlv_id)
        _ch_Sub = binascii.a2b_hex(ch_Sub)
        _ch_Id_Str = binascii.a2b_hex(chID_Str)
        _len = struct.pack(">B", (_ch_Id_Str.__len__() + _ch_Sub.__len__()))
        _path = _tlv_ID + _len + _ch_Sub + _ch_Id_Str
        return bytearray(binascii.b2a_hex(_path))

    def make_subtype_layer(self, tlv_type, prt_type, prt_id_str):
        """
        Port ID TLV layer consists of 4 parameters:
        Type: (1b) it's always equal 2
        Length: (1b) length of parameters 3 and 4, and it's size should be <= 34:
        Port ID Type: This parameter can take a value between 1 and 4
         =1 -> set ifAlias for the source port
         =2 -> set entPhysicalAlias for the port
         =3 -> MAC address for the port
         =4 -> A management address for the port
         Port ID string - name of the port type e.g. eth0
        """
        _tlv_type = binascii.a2b_hex(tlv_type)
        _prt_type = binascii.a2b_hex(prt_type)
        _prt_id_str = binascii.a2b_hex(prt_id_str)
        _len = struct.pack(">B", (_prt_id_str.__len__() + _prt_type.__len__()))
        _path = _tlv_type + _len + _prt_type + _prt_id_str
        return bytearray(binascii.b2a_hex(_path))

    def make_ttl_layer(self, ttl_type, time_to_live):
        """
        Function creates TTL layer part of LLDP protocol

        Type: 1b its always equal 3
        Length 1b size of the lifetime variable
        ttl variable representing lifetime of the packet

        """

        _ttl_type = binascii.a2b_hex(ttl_type)
        _time_to_live = binascii.a2b_hex(time_to_live)
        _len = struct.pack(">B", _time_to_live.__len__())
        _path = _ttl_type + _len + _time_to_live
        return bytearray(binascii.b2a_hex(_path))

    def make_configuration_status_layer(self, tlvl_type, org_code, org_subtype, nego_status, pmd_cap, bit_order,
                                        mau_type):
        """
        Function creates TTL layer part of LLDP protocol

        Type: 1b its always equal 3
        Length 1b size of the lifetime variable
        ttl variable representing lifetime of the packet

        """

        _tlvl_type = binascii.a2b_hex(tlvl_type)
        _org_code = binascii.a2b_hex(org_code)
        _org_subtype = binascii.a2b_hex(org_subtype)
        _nego_status = binascii.a2b_hex(nego_status)
        _pmd_cap = binascii.a2b_hex(pmd_cap)
        _bit_order = binascii.a2b_hex(bit_order)
        _mau_type = binascii.a2b_hex(mau_type)
        len = _org_code.__len__() + _org_subtype.__len__() + _nego_status.__len__() + _pmd_cap.__len__() + _bit_order.__len__() + _mau_type.__len__()
        _len = struct.pack(">B", len)
        _path = _tlvl_type + _len + _org_code + _org_subtype + _nego_status + _pmd_cap + _bit_order + _mau_type
        return bytearray(binascii.b2a_hex(_path))

    def media_cap_layer(self, tvl_type, org_unicode, media_subtype, cap, cls_typ):
        """
        Function creates TTL layer part of LLDP protocol

        Type: 1b its always equal 3
        Length 1b size of the lifetime variable
        ttl variable representing lifetime of the packet

        """
        _tvl_type = binascii.a2b_hex(tvl_type)
        _org_unicode = binascii.a2b_hex(org_unicode)
        _media_subtype = binascii.a2b_hex(media_subtype)
        _cap = binascii.a2b_hex(cap)
        _cls_typ = binascii.a2b_hex(cls_typ)
        _len = struct.pack(">B",
                           (_org_unicode.__len__() + _media_subtype.__len__() + _cap.__len__() + _cls_typ.__len__()))
        _path = _tvl_type + _len + _org_unicode + _media_subtype + _cap + _cls_typ
        return bytearray(binascii.b2a_hex(_path))

    def port_description_layer(self, tvl_type, org_unicode, media_subtype, cap, cls_typ):
        """
        Function creates Port Description layer part of LLDP protocol (TTL = 4)

        """
        _tvl_type = binascii.a2b_hex(tvl_type)
        _org_unicode = binascii.a2b_hex(org_unicode)
        _media_subtype = binascii.a2b_hex(media_subtype)
        _cap = binascii.a2b_hex(cap)
        _cls_typ = binascii.a2b_hex(cls_typ)
        _len = struct.pack(">B",
                           (_org_unicode.__len__() + _media_subtype.__len__() + _cap.__len__() + _cls_typ.__len__()))
        _path = _tvl_type + _len + _org_unicode + _media_subtype + _cap + _cls_typ
        return bytearray(binascii.b2a_hex(_path))

    def port_desc_layer(self):
        """
        Function creates System Layer layer part of LLDP protocol (TTL = 4)
        "Rockwell"
        """
        _tvl_type = binascii.a2b_hex("08")
        _system_name = binascii.a2b_hex("1218")
        _len = struct.pack(">B", _system_name.__len__())
        _path = _tvl_type + _len + _system_name
        return bytearray(binascii.b2a_hex(_path))

    def system_name_layer(self):
        """
        Function creates System Layer layer part of LLDP protocol (TTL = 5)
        "Rockwell"
        """
        _tvl_type = binascii.a2b_hex("0a")
        _system_name = binascii.a2b_hex("526f636b77656c6c")
        _len = struct.pack(">B", _system_name.__len__())
        _path = _tvl_type + _len + _system_name
        return bytearray(binascii.b2a_hex(_path))

    def system_description_layer(self):
        """
        Function creates System Layer layer part of LLDP protocol (TTL = 6)
        "Automation"
        """
        _tvl_type = binascii.a2b_hex("0c")
        _system_name = binascii.a2b_hex("4175746f6d6174696f6e")
        _len = struct.pack(">B", _system_name.__len__())
        _path = _tvl_type + _len + _system_name
        return bytearray(binascii.b2a_hex(_path))

    def management_address_Layer(self, tlv, adr_len, adr_sub, ip, interf_sub, intef_num, OID):
        """
        Function creates System Layer layer part of LLDP protocol (TTL = 8)
        "Automation"
        """
        _tvl_type = binascii.a2b_hex(tlv)
        _addr_str_len = binascii.a2b_hex(adr_len)
        _addr_subtype = binascii.a2b_hex(adr_sub)
        _ip_addrr = binascii.a2b_hex(ip)
        _interface_subtype = binascii.a2b_hex(interf_sub)
        _interface_numb = binascii.a2b_hex(intef_num)
        _odd_len = binascii.a2b_hex(OID)

        _len = struct.pack(">B", _addr_str_len.__len__() + _addr_subtype.__len__() + _ip_addrr.__len__() +
                           _interface_subtype.__len__() + _interface_numb.__len__() + _odd_len.__len__())
        _path = _tvl_type + _len + _addr_str_len + _addr_subtype + _ip_addrr + _interface_subtype + _interface_numb + _odd_len
        return bytearray(binascii.b2a_hex(_path))

    def sys_capab_layer(self, sys_cap_ID, sys_cap):
        """
        Function creates System Layer layer part of LLDP protocol (TTL = 7)
        "Automation"
        """
        _tvl_type = binascii.a2b_hex(sys_cap_ID)
        _system_cap = binascii.a2b_hex(sys_cap)
        _len = struct.pack(">B", 2 * _system_cap.__len__())
        _path = _tvl_type + _len + _system_cap + _system_cap
        return bytearray(binascii.b2a_hex(_path))

    def make_end_frame(self, end):
        """
        Function creates TTL layer part of LLDP protocol

        Type: 1b its always equal 3
        Length 1b size of the lifetime variable
        ttl variable representing lifetime of the packet

        """
        _end = binascii.a2b_hex(end)
        return bytearray(binascii.b2a_hex(_end))


# noinspection PyTypeChecker
class LLDP_Tests(SocketCreator):
    def __init__(self, interface):
        self.socketMaker = SocketCreator()
        self.interface = interface

    def send_lldp_message(self, frame_dst, frame_scr, tlv_id, chSub, chID, tlv_type, prt_type, prt_id_str, ttl_type,
                          time_to_live, tlvl_type, org_code, org_subtype, nego_status, pmd_cap, bit_order,
                          mau_type, tvl_type, org_unicode, media_subtype, cap, cls_typ):
        """
        Function creates LLDP packet that will be sent on LLDP_Broadcast mac address. It's size and amount of data
        depends on the TLV parameter that represents specific data that will be sent:
        TLV = 0 -> endframe of the LLDP packet - it is represented by "00 00"
        TLV = 1 -> chassis ID
        TLV = 2 -> port ID
        TLV = 3 -> time to live
        TLV = 4 -> Port Description
        TLV = 5 -> System name
        TLV = 6 -> System Description
        TLV = 7 -> System Capabilities
        TLV = 8 -> Management address
        TLV = 127 -> Organizationally specific data
        """
        end = "0000"
        chasis_subtype = self.socketMaker.make_chasis_layer(tlv_id, chSub, chID)
        port_subtype = self.socketMaker.make_subtype_layer(tlv_type, prt_type, prt_id_str)
        ttl_subtype = self.socketMaker.make_ttl_layer(ttl_type, time_to_live)
        sys_name = self.socketMaker.system_name_layer()
        sys_desc = self.socketMaker.system_description_layer()
        manage_addr = self.socketMaker.management_address_Layer(tlv="10", adr_len="05", adr_sub="01", ip="c0a80109",
                                                                interf_sub="02", intef_num="00000005", OID="00")
        capabil_layer = self.socketMaker.sys_capab_layer(sys_cap_ID="0e", sys_cap="0080")
        prt_des_layer = self.socketMaker.port_desc_layer()
        conf_layer = self.socketMaker.make_configuration_status_layer(tlvl_type, org_code, org_subtype, nego_status,
                                                                      pmd_cap, bit_order, mau_type)
        media_cap_layer = self.socketMaker.media_cap_layer(tvl_type, org_unicode, media_subtype, cap, cls_typ)
        end_frame = self.socketMaker.make_end_frame(end)
        destination = frame_dst
        source = frame_scr
        payload = chasis_subtype + port_subtype + ttl_subtype + prt_des_layer + sys_name + sys_desc + manage_addr + conf_layer + capabil_layer + media_cap_layer + end_frame
        packet = (Ether(dst=destination, src=source, type=0x88cc) /
                  Raw(load=bytearray(binascii.a2b_hex(payload))))

        sendp(packet, iface=self.interface)
