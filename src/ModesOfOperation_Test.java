public class ModesOfOperation_Test {
    public static void main(String[] args) {
       OMAC omac_test = new OMAC();
       long[] res = omac_test.getMAC("resources/test.txt", "1234567887654321");
       System.out.println();
    }
}
