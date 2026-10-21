package ee.ria.govsso.model

enum Actuator {
    HEALTH("/actuator/health"),
    LIVENESS("/actuator/health/liveness"),
    READINESS("/actuator/health/readiness"),
    INFO("/actuator/info"),
    PROMETHEUS("/actuator/prometheus")

    final String path

    Actuator(String path) {
        this.path = path
    }

    @Override
    String toString() {
        path
    }
}
