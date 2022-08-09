import scala.util.Try;
import org.ergoplatform.simpleaddresses.ErgoAddressEncoder;
import org.ergoplatform.simpleaddresses.MainnetAddressEncoder;
import org.ergoplatform.simpleaddresses.ErgoAddress;
import org.ergoplatform.simpleaddresses.P2PKAddress;

public class AddressTester {
    private boolean isP2PKAddress(String address) {
        try {
            ErgoAddressEncoder encoder = new MainnetAddressEncoder();
            ErgoAddress ergoAddress = encoder.fromString(address);
            if (ergoAddress instanceof P2PKAddress) {
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static void main(String[] args) {
        AddressTester tester = new AddressTester();
        System.out.println(tester.isP2PKAddress("9eYPzx6nogBjex83aiGemfdj579qxD3TPRiPRNHyLZRG8S7rLuQ"));
    }
}
