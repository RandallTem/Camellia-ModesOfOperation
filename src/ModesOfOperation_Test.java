public class ModesOfOperation_Test {
    public static void main(String[] args) {
        CBC cbc_test = new CBC();
        cbc_test.Encrypt("resources/test.txt", "12345678");
        cbc_test.Decrypt("resources/test.txt.crptd", "12345678");
    }
}
