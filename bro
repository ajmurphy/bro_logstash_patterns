#Copyright (c) 2016, Austin Murphy
#All rights reserved.

#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

#1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

#2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

#3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#Created from the specification provided at https://www.bro.org/sphinx/script-reference/log-files.html

# http.log
BRO_HTTP %{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{INT:trans_depth}\t%{GREEDYDATA:method}\t%{GREEDYDATA:domain}\t%{GREEDYDATA:uri}\t%{GREEDYDATA:referrer}\t%{GREEDYDATA:user_agent}\t%{NUMBER:request_body_len}\t%{NUMBER:response_body_len}\t%{GREEDYDATA:status_code}\t%{GREEDYDATA:status_msg}\t%{GREEDYDATA:info_code}\t%{GREEDYDATA:info_msg}\t%{GREEDYDATA:filename}\t%{GREEDYDATA:bro_tags}\t%{GREEDYDATA:username}\t%{GREEDYDATA:password}\t%{GREEDYDATA:proxied}\t%{GREEDYDATA:orig_fuids}\t%{GREEDYDATA:orig_mime_types}\t%{GREEDYDATA:resp_fuids}\t%{GREEDYDATA:resp_mime_types}

# dns.log
BRO_DNS %{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{WORD:proto}\t%{INT:trans_id}\t%{GREEDYDATA:query}\t%{GREEDYDATA:qclass}\t%{GREEDYDATA:qclass_name}\t%{GREEDYDATA:qtype}\t%{GREEDYDATA:qtype_name}\t%{GREEDYDATA:rcode}\t%{GREEDYDATA:rcode_name}\t%{GREEDYDATA:AA}\t%{GREEDYDATA:TC}\t%{GREEDYDATA:RD}\t%{GREEDYDATA:RA}\t%{GREEDYDATA:Z}\t%{GREEDYDATA:answers}\t%{GREEDYDATA:TTLs}\t%{GREEDYDATA:rejected}

# conn.log
BRO_CONN %{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{WORD:proto}\t%{GREEDYDATA:service}\t%{NOTSPACE:duration}\t%{NOTSPACE:orig_bytes:int}\t%{NOTSPACE:resp_bytes:int}\t%{NOTSPACE:conn_state}\t%{NOTSPACE:local_orig}\t%{NOTSPACE:local_resp}\t%{NOTSPACE:missed_bytes:int}\t%{NOTSPACE:history}\t%{NOTSPACE:orig_pkts:int}\t%{NOTSPACE:orig_ip_bytes:int}\t%{NOTSPACE:resp_pkts:int}\t%{NOTSPACE:resp_ip_bytes:int}\t%{NOTSPACE:tunnel_parents}\t%{NOTSPACE:oric_cc}\t%{NOTSPACE:resp_cc}\t%{NOTSPACE:sensorname}

# files.log
BRO_FILES %{NUMBER:ts}\t%{NOTSPACE:fuid}\t%{IP:tx_hosts}\t%{IP:rx_hosts}\t%{NOTSPACE:conn_uids}\t%{GREEDYDATA:source}\t%{GREEDYDATA:depth}\t%{GREEDYDATA:analyzers}\t%{GREEDYDATA:mime_type}\t%{GREEDYDATA:filename}\t%{GREEDYDATA:duration}\t%{GREEDYDATA:local_orig}\t%{GREEDYDATA:is_orig}\t%{GREEDYDATA:seen_bytes}\t%{GREEDYDATA:total_bytes}\t%{GREEDYDATA:missing_bytes}\t%{GREEDYDATA:overflow_bytes}\t%{GREEDYDATA:timedout}\t%{GREEDYDATA:parent_fuid}\t%{GREEDYDATA:md5}\t%{GREEDYDATA:sha1}\t%{GREEDYDATA:sha256}\t%{GREEDYDATA:extracted}

# ssl.log
BRO_SSL %{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{GREEDYDATA:version}\t%{GREEDYDATA:cipher}\t%{GREEDYDATA:curve}\t%{NOTSPACE:server_name}\t%{NOTSPACE:resumed}\t%{NOTSPACE:last_alert}\t%{NOTSPACE:next_protocol}\t%{GREEDYDATA:established}\t%{GREEDYDATA:cert_chain_fuids}\t%{GREEDYDATA:client_cert_chain_fuids}\t%{GREEDYDATA:subject}\t%{GREEDYDATA:issuer}\t%{GREEDYDATA:client_subject}\t%{GREEDYDATA:client_issuer}\t%{GREEDYDATA:validation_status}

# ssh.log
BRO_SSH %{NUMBER:ts}\t%{NOTSPACE:uid}\t%{IP:orig_h}\t%{INT:orig_p}\t%{IP:resp_h}\t%{INT:resp_p}\t%{GREEDYDATA:version}\t%{GREEDYDATA:auth_success}\t%{GREEDYDATA:direction}\t%{GREEDYDATA:client}\t%{GREEDYDATA:server}\t%{GREEDYDATA:cipher_alg}\t%{GREEDYDATA:mac_alg}\t%{GREEDYDATA:compression_alg}\t%{GREEDYDATA:kex_alg}\t%{GREEDYDATA:host_key_alg}\t%{GREEDYDATA:host_key}\t%{GREEDYDATA:remote_loc_country_code}\t%{GREEDYDATA:remote_loc_region}\t%{GREEDYDATA:remote_loc_city}\t%{GREEDYDATA:remote_loc_lat}\t%{GREEDYDATA:remote_loc_long}

#bro.x509
BRO_X509 %{NUMBER:ts}\t%{NOTSPACE:id}\t%{GREEDYDATA:certificate_version}\t%{GREEDYDATA:certificate_serial}\t%{GREEDYDATA:certificate_subject}\t%{GREEDYDATA:certificate_issuer}\t%{GREEDYDATA:certificate_not_valid_before}\t%{GREEDYDATA:certificate_not_valid_after}\t%{GREEDYDATA:certificate_key_alg}\t%{GREEDYDATA:certificate_sig_alg}\t%{GREEDYDATA:certificate_key_type}\t%{GREEDYDATA:certificate_key_length}\t%{GREEDYDATA:certificate_exponent}\t%{GREEDYDATA:certificate_curve}\t%{GREEDYDATA:san_dns}\t%{GREEDYDATA:san_uri}\t%{GREEDYDATA:san_email}\t%{GREEDYDATA:san_ip}\t%{GREEDYDATA:basic_constraints_ca}\t%{GREEDYDATA:basic_constraints_path_len}
