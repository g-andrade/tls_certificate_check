
all: good_ca_store_for_expiry
all: bad_ca_store_for_expiry
all: ca_store1_for_cross_signing
all: ca_store2_for_cross_signing
all: localhost_chain_for_expiry
all: localhost_chain_for_cross_signing

good_ca_store_for_expiry: new_ca
good_ca_store_for_expiry: expired_ca
good_ca_store_for_expiry:
	cat expired_ca.pem new_ca.pem >good_ca_store_for_expiry.pem
.PHONY: good_ca_store_for_expiry

bad_ca_store_for_expiry: expired_ca
bad_ca_store_for_expiry:
	cat expired_ca.pem >bad_ca_store_for_expiry.pem
.PHONY: bad_ca_store_for_expiry

ca_store1_for_cross_signing: third_ca
	cat new_ca.pem >ca_store1_for_cross_signing.pem

ca_store2_for_cross_signing: third_ca
	cat third_ca.pem >ca_store2_for_cross_signing.pem

localhost_chain_for_expiry: localhost
localhost_chain_for_expiry: regular_intermediate_cert
localhost_chain_for_expiry: cross_signed_bad_intermediate_cert
	cat \
		localhost.pem \
		regular_intermediate_cert.pem \
		cross_signed_bad_intermediate_cert.pem \
		>localhost_chain_for_expiry.pem
.PHONY: localhost_chain

localhost_chain_for_cross_signing: localhost
localhost_chain_for_cross_signing: regular_intermediate_cert
localhost_chain_for_cross_signing: cross_signed_good_intermediate_cert
	cat \
		localhost.pem \
		regular_intermediate_cert.pem \
		cross_signed_good_intermediate_cert.pem \
		>localhost_chain_for_cross_signing.pem
.PHONY: localhost_chain

localhost: regular_intermediate_cert
localhost: localhost.csr
localhost: faketime
localhost:
	faketime -f '-5y' openssl x509 \
		-req \
		-in localhost.csr \
		-CA regular_intermediate_cert.pem \
		-CAkey regular_intermediate_cert_key.pem \
		-CAcreateserial \
		-out localhost.pem \
		-days 3600 \
		-sha256
.PHONY: localhost

regular_intermediate_cert: new_ca
regular_intermediate_cert: regular_intermediate_cert.csr
regular_intermediate_cert: faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in regular_intermediate_cert.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA new_ca.pem \
		-CAkey new_ca_key.pem \
		-CAcreateserial \
		-out regular_intermediate_cert.pem \
		-days 3600 \
		-sha256
.PHONY: regular_intermediate_cert

cross_signed_bad_intermediate_cert: expired_ca
cross_signed_bad_intermediate_cert: new_ca.csr
cross_signed_bad_intermediate_cert: faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in new_ca.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA expired_ca.pem \
		-CAkey expired_ca_key.pem \
		-CAcreateserial \
		-out cross_signed_bad_intermediate_cert.pem \
		-days 3600 \
		-sha256
.PHONY: cross_signed_bad_intermediate_cert

cross_signed_good_intermediate_cert: third_ca
cross_signed_good_intermediate_cert: new_ca.csr
cross_signed_good_intermediate_cert: faketime
	faketime -f '-5y' openssl x509 \
		-req \
		-in new_ca.csr \
		-extfile intermediate_ca.ext \
		-extensions v3_intermediate_ca \
		-CA third_ca.pem \
		-CAkey third_ca_key.pem \
		-CAcreateserial \
		-out cross_signed_good_intermediate_cert.pem \
		-days 3600 \
		-sha256
.PHONY: cross_signed_good_intermediate_cert

expired_ca: faketime
expired_ca: expired_ca_key.pem
	faketime -f '-5y' openssl req -x509 \
		-new -nodes \
		-key expired_ca_key.pem \
		-sha256 \
		-days 1800 \
		-subj "/CN=Expired CA" \
		-out expired_ca.pem
.PHONY: expired_ca

faketime:
	./install_faketime.sh
.PHONY: faketime

.PRECIOUS: %_ca # prevens removal of what is considered an intermediate file (FIXME untested on macos)
%_ca: %_ca_key.pem faketime
	faketime -f '-5y' openssl req -x509 \
		-new -nodes \
		-key $*_ca_key.pem \
		-sha256 \
		-days 3600 \
		-subj "/CN=$*_ca" \
		-out $*_ca.pem
.PHONY: %_ca

.PRECIOUS: %_key.pem # prevens removal of what is considered an intermediate file (FIXME untested on macos)
%.csr: %_key.pem
	openssl req \
		-new \
		-key $*_key.pem \
		-subj "/CN=$*" \
		-out $@

.PRECIOUS: %_key.pem # prevens removal of what is considered an intermediate file (FIXME untested on macos)
%_key.pem:
	openssl genrsa -out $@ 2048
