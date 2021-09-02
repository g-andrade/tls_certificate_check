
all: leaf_certificates/good_certificate.pem
all: leaf_certificates/expired_certificate.pem
all: leaf_certificates/future_certificate.pem
all: leaf_certificates/wrong.host.pem
all: leaf_certificates/self_signed.pem
all: leaf_certificates/unknown_ca.pem
all: certificate_chains/misordered_chain.pem
all: CA_stores/foobar.pem

clean:
	find . -mindepth 2 -maxdepth 2 -type f \( -name '*.pem' -or -name '*.csr' -or -name '*.srl' \) -delete

certificate_chains/misordered_chain.pem: CAs/foobar_ca.pem
certificate_chains/misordered_chain.pem: intermediate_certificates/intermediate_cert.pem
certificate_chains/misordered_chain.pem: leaf_certificates/good_certificate_with_intermediate_ca.pem
	cat \
		leaf_certificates/good_certificate_with_intermediate_ca.pem \
		CAs/foobar_ca.pem \
		intermediate_certificates/intermediate_cert.pem \
		>certificate_chains/misordered_chain.pem

leaf_certificates/good_certificate.pem: CAs/foobar_ca.pem
leaf_certificates/good_certificate.pem: leaf_certificates/localhost.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA CAs/foobar_ca.pem \
		-CAkey CAs/foobar_ca_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 20075 \
		-sha256

leaf_certificates/expired_certificate.pem: CAs/foobar_ca.pem
leaf_certificates/expired_certificate.pem: leaf_certificates/localhost.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA CAs/foobar_ca.pem \
		-CAkey CAs/foobar_ca_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 1800 \
		-sha256

leaf_certificates/future_certificate.pem: CAs/foobar_ca.pem
leaf_certificates/future_certificate.pem: leaf_certificates/localhost.csr
	faketime -f '+50y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA CAs/foobar_ca.pem \
		-CAkey CAs/foobar_ca_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 1800 \
		-sha256

leaf_certificates/wrong.host.pem: CAs/foobar_ca.pem
leaf_certificates/wrong.host.pem: leaf_certificates/wrong.host.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/wrong.host.csr \
		-CA CAs/foobar_ca.pem \
		-CAkey CAs/foobar_ca_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 20075 \
		-sha256

leaf_certificates/self_signed.pem: leaf_certificates/self_signed_key.pem
	faketime -f '-5y' openssl req -x509 \
		-new -nodes \
		-key leaf_certificates/self_signed_key.pem \
		-sha256 \
		-days 20075 \
		-subj '/CN=localhost' \
		-out $@

leaf_certificates/unknown_ca.pem: CAs/another_ca.pem
leaf_certificates/unknown_ca.pem: leaf_certificates/localhost.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA CAs/another_ca.pem \
		-CAkey CAs/another_ca_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 20075 \
		-sha256

intermediate_certificates/intermediate_cert.pem: CAs/foobar_ca.pem
intermediate_certificates/intermediate_cert.pem: intermediate_certificates/intermediate_cert.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in intermediate_certificates/intermediate_cert.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA CAs/foobar_ca.pem \
		-CAkey CAs/foobar_ca_key.pem \
		-CAcreateserial \
		-out intermediate_certificates/intermediate_cert.pem \
		-days 20075 \
		-sha256

leaf_certificates/good_certificate_with_intermediate_ca.pem: intermediate_certificates/intermediate_cert.pem
leaf_certificates/good_certificate_with_intermediate_ca.pem: leaf_certificates/localhost.csr
	faketime -f '-5y' openssl x509 \
		-req \
		-in leaf_certificates/localhost.csr \
		-CA intermediate_certificates/intermediate_cert.pem \
		-CAkey intermediate_certificates/intermediate_cert_key.pem \
		-CAcreateserial \
		-out $@ \
		-days 20075 \
		-sha256

CA_stores/foobar.pem: CAs/foobar_ca.pem
	cat \
		CAs/foobar_ca.pem \
		>CA_stores/foobar.pem


.PRECIOUS: %_ca.pem # prevents removal of what is considered an intermediate file (FIXME untested on macos)
%_ca.pem: %_ca_key.pem
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
