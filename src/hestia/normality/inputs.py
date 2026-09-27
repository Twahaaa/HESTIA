"""Pure mapping from session features to estimator inputs."""

from hestia.normality.models import ModelCompatibilityError


def model_input(model_id: str, features: object) -> object:
    if model_id == "login_hour_rarity":
        return features.login_hour_local
    if model_id == "auth_frequency":
        return float(features.auth_frequency_window_count)
    if model_id == "src_ip_behavior":
        return {
            "failure_proportion": features.failure_proportion,
            "success_proportion": features.success_proportion,
            "distinct_hosts_in_session": float(features.distinct_hosts_in_session),
            "distinct_users_for_src_ip": float(
                features.materialized_context.distinct_users_for_src_ip
            ),
            "hour_sin": features.hour_sin,
            "hour_cos": features.hour_cos,
        }
    if model_id == "host_access":
        return {
            "failure_proportion": features.failure_proportion,
            "success_proportion": features.success_proportion,
            "event_count": float(features.event_count),
            "distinct_users_for_host": float(features.materialized_context.distinct_users_for_host),
            "distinct_src_ips_for_host": float(
                features.materialized_context.distinct_src_ips_for_host
            ),
            "hour_sin": features.hour_sin,
            "hour_cos": features.hour_cos,
        }
    if model_id == "transition_surprise":
        return features.event_types
    raise ModelCompatibilityError(f"Unknown model ID: {model_id!r}")
