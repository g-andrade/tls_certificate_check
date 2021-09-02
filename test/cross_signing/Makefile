
all: CA_stores/good_ca_store_for_expiry.pem
all: CA_stores/bad_ca_store_for_expiry.pem
all: CA_stores/ca_store1_for_cross_signing.pem
all: CA_stores/ca_store2_for_cross_signing.pem
all: certificate_chains/localhost_chain_for_expiry.pem
all: certificate_chains/localhost_chain_for_cross_signing.pem

clean:
	find . -mindepth 2 -maxdepth 2 -type f \( -name '*.pem' -or -name '*.csr' -or -name '*.srl' \) -delete
	rm -f .faketime

CA_stores/good_ca_store_for_expiry.pem: CAs/new_ca.pem
CA_stores/good_ca_store_for_expiry.pem: CAs/expired_ca.pem
CA_stores/good_ca_store_for_expiry.pem:
	cat \
		CAs/expired_ca.pem \
		CAs/new_ca.pem \
		>CA_stores/good_ca_store_for_expiry.pem

CA_stores/bad_ca_store_for_expiry.pem: CAs/expired_ca.pem
CA_stores/bad_ca_store_for_expiry.pem:
	cat \
		CAs/expired_ca.pem \
		>CA_stores/bad_ca_store_for_expiry.pem

CA_stores/ca_store1_for_cross_signing.pem: CAs/new_ca.pem
	cat \
		CAs/new_ca.pem \
		>CA_stores/ca_store1_for_cross_signing.pem

CA_stores/ca_store2_for_cross_signing.pem: CAs/third_ca.pem
	cat \
		CAs/third_ca.pem \
		>CA_stores/ca_store2_for_cross_signing.pem

certificate_chains/localhost_chain_for_expiry.pem: leaf_certificates/localhost.pem
certificate_chains/localhost_chain_for_expiry.pem: intermediate_certificates/regular_intermediate_cert.pem
certificate_chains/localhost_chain_for_expiry.pem: intermediate_certificates/cross_signed_bad_intermediate_cert.pem
	cat \
		leaf_certificates/localhost.pem \
		intermediate_certificates/regular_intermediate_cert.pem \
		intermediate_certificates/cross_signed_bad_intermediate_cert.pem \
		>certificate_chains/localhost_chain_for_expiry.pem

certificate_chains/localhost_chain_for_cross_signing.pem: leaf_certificates/localhost.pem
certificate_chains/localhost_chain_for_cross_signing.pem: intermediate_certificates/regular_intermediate_cert.pem
certificate_chains/localhost_chain_for_cross_signing.pem: intermediate_certificates/cross_signed_good_intermediate_cert.pem
	cat \
		leaf_certificates/localhost.pem \
		intermediate_certificates/regular_intermediate_cert.pem \
		intermediate_certificates/cross_signed_good_intermediate_cert.pem \
		>certificate_chains/localhost_chain_for_cross_signing.pem

leaf_certificates/localhost.pem: intermediate_certificates/regular_intermediate_cert.pem
leaf_certificates/localhost.pem: leaf_certificates/localhost.csr
leaf_certificates/localhost.pem: .faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA intermediate_certificates/regular_intermediate_cert.pem \
		-CAkey intermediate_certificates/regular_intermediate_cert_key.pem \
		-CAcreateserial \
		-out leaf_certificates/localhost.pem \
		-days 20075 \
		-sha256

intermediate_certificates/regular_intermediate_cert.pem: CAs/new_ca.pem
intermediate_certificates/regular_intermediate_cert.pem: intermediate_certificates/regular_intermediate_cert.csr
intermediate_certificates/regular_intermediate_cert.pem: .faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in intermediate_certificates/regular_intermediate_cert.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA CAs/new_ca.pem \
		-CAkey CAs/new_ca_key.pem \
		-CAcreateserial \
		-out intermediate_certificates/regular_intermediate_cert.pem \
		-days 20075 \
		-sha256

intermediate_certificates/cross_signed_bad_intermediate_cert.pem: CAs/expired_ca.pem
intermediate_certificates/cross_signed_bad_intermediate_cert.pem: CAs/new_ca.csr
intermediate_certificates/cross_signed_bad_intermediate_cert.pem: .faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in CAs/new_ca.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA CAs/expired_ca.pem \
		-CAkey CAs/expired_ca_key.pem \
		-CAcreateserial \
		-out intermediate_certificates/cross_signed_bad_intermediate_cert.pem \
		-days 20075 \
		-sha256

intermediate_certificates/cross_signed_good_intermediate_cert.pem: CAs/third_ca.pem
intermediate_certificates/cross_signed_good_intermediate_cert.pem: CAs/new_ca.csr
intermediate_certificates/cross_signed_good_intermediate_cert.pem: .faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in CAs/new_ca.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA CAs/third_ca.pem \
		-CAkey CAs/third_ca_key.pem \
		-CAcreateserial \
		-out intermediate_certificates/cross_signed_good_intermediate_cert.pem \
		-days 20075 \
		-sha256

CAs/expired_ca.pem: .faketime
CAs/expired_ca.pem: CAs/expired_ca_key.pem
	faketime -f '-5y' openssl req -x509 \
		-new -nodes \
		-key CAs/expired_ca_key.pem \
		-sha256 \
		-days 1800 \
		-subj "/CN=Expired CA" \
		-out CAs/expired_ca.pem

.faketime:
	./install_faketime.sh;
	touch .faketime

.PRECIOUS: %_ca.pem # prevents removal of what is considered an intermediate file (FIXME untested on macos)
%_ca.pem: %_ca_key.pem .faketime
	faketime -f '-5y' openssl req -x509 \
		-new -nodes \
		-key $*_ca_key.pem \
		-sha256 \
		-days 20075 \
		-subj "/CN=$(*F)_ca" \
		-out $@

.PRECIOUS: %_key.pem # prevents removal of what is considered an intermediate file (FIXME untested on macos)
%.csr: %_key.pem
	openssl req \
		-new \
		-key $*_key.pem \
		-subj "/CN=$(*F)" \
		-out $@

.PRECIOUS: %_key.pem # prevents removal of what is considered an intermediate file (FIXME untested on macos)
%_key.pem:
	openssl genrsa -out $@ 2048
