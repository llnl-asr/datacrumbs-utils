// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
#define DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__

#include <string>

namespace datacrumbs::probe_signing_service {

/**
 * @brief Return probe-manager TCP host used for signing RPC.
 * @return Hostname or IP string.
 */
std::string tcp_host();

/**
 * @brief Return probe-manager TCP port used for signing RPC.
 * @return TCP port number.
 */
int tcp_port();

/**
 * @brief Request a signed probe document for a serialized signing payload.
 *
 * The request is authenticated with a munge credential bound to the payload, so
 * the manager derives the requesting uid from munged rather than from anything
 * this process claims. The manager injects identity and expiry fields into the
 * summary before signing, which means the returned document differs from what
 * was sent and must be persisted verbatim -- a locally rebuilt document would
 * not match the signature.
 *
 * @param signing_payload Serialized JSON payload sent to manager.
 *        Example: "{\"summary\":{...},\"categories\":[...]}".
 * @param signed_document Output complete signed document on success.
 * @param error Optional output error message on failure.
 * @return True when the request succeeds and signed_document is set.
 */
bool request_signed_probe_document(const std::string& signing_payload,
                                   std::string* signed_document, std::string* error = nullptr);

}  // namespace datacrumbs::probe_signing_service

#endif  // DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
