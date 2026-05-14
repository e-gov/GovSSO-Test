package ee.ria.govsso.model

enum LoA {

    HIGH("high", "E"),
    SUBSTANTIAL("substantial", "C"),
    LOW("low", "A"),

    final String label
    final String eidasTestCaLoa

    LoA(String label, String eidasTestCaLoa) {
        this.label = label
        this.eidasTestCaLoa = eidasTestCaLoa
    }

    String getEidasTestCaLoa() {
        return eidasTestCaLoa
    }

    String toString() {
        return label
    }
}
