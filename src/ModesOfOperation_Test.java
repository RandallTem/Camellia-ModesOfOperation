public class ModesOfOperation_Test {
    public static void main(String[] args) {
       OFB ofb_test = new OFB();
       ofb_test.Encrypt("resources/File_5MB.txt", "1234567887654321");
       ofb_test.Decrypt("resources/File_5MB.txt.crptd", "1234567887654321");
    }
}
