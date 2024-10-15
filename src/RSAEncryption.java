import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RSAEncryption {
	private BigInteger n, e, d, phi;
	private int bitLength = 4096;

	public RSAEncryption() {
	}

	public RSAEncryption(int bitLength) {
		this.bitLength = bitLength;
	}

	public RSAEncryption(BigInteger n, BigInteger e, BigInteger d) {
		this.n = n;
		this.e = e;
		this.d = d;
	}

	/*
	 * Key Generation
	 */

	public void GenerateKeys() {
		// Get prime numbers
		BigInteger p = BigInteger.probablePrime(bitLength, new java.util.Random());
		BigInteger q = BigInteger.probablePrime(bitLength, new java.util.Random());
		n = p.multiply(q);
		// Calculate phi = (p-1)*(q-1)
		phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = GeneratePublicKey();
		// Calculate d using the Eucledian Algorithm and ensure d is positive
		d = ExtendedEuclid(phi, e).y.mod(phi);
	}

	// Extended Euclidean Algorithm
	public ExtendedEuclidResult ExtendedEuclid(BigInteger a, BigInteger b) {
		BigInteger x0 = BigInteger.ONE;
		BigInteger y0 = BigInteger.ZERO;
		BigInteger x1 = BigInteger.ZERO;
		BigInteger y1 = BigInteger.ONE;

		while (!b.equals(BigInteger.ZERO)) {
			BigInteger[] qr = a.divideAndRemainder(b);
			// qr[0] = quotient, qr[1] = remainder
			a = b;
			b = qr[1];

			BigInteger tmpX = x0;
			BigInteger tmpY = y0;
			x0 = x1;
			y0 = y1;
			x1 = tmpX.subtract(qr[0].multiply(x1));
			y1 = tmpY.subtract(qr[0].multiply(y1));
		}

		return new ExtendedEuclidResult(a, x0, y0);
	}

	// Find a number e that has the ggt with phi == 1
	private BigInteger GeneratePublicKey() {
		BigInteger e = new BigInteger("65537");
		while (!ExtendedEuclid(phi, e).ggt.equals(BigInteger.ONE)) {
			e = new BigInteger(bitLength, new java.util.Random());
		}
		return e;
	}

	/*
	 * Encryption and Decryption
	 */

	// Fast Exponentiation Algorithm
	public BigInteger FastExponentiation(BigInteger x, BigInteger e, BigInteger m) {
		BigInteger h = BigInteger.ONE;
		BigInteger k = x.mod(m);
		// Create the binary string for the exponent
		String b = e.abs().toString(2);
		for (int i = b.length() - 1; i >= 0; i--) {
			if (b.charAt(i) == '1') {
				h = h.multiply(k).mod(m);
			}
			k = k.multiply(k).mod(m);
		}
		return h;
	}

	// Probably the better way to do it
	public BigInteger FastExponentiation2(BigInteger x, BigInteger e, BigInteger m) {
		BigInteger h = BigInteger.ONE;
		BigInteger k = x.mod(m);
		// While e > 0
		while (e.signum() > 0) {
			// If e is odd (reading last bit)
			if (e.and(BigInteger.ONE).compareTo(BigInteger.ONE) == 0) {
				h = h.multiply(k).mod(m);
			}
			k = k.multiply(k).mod(m);
			// Shift right (going to next bit)
			e = e.shiftRight(1);
		}
		return h;
	}

	private BigInteger Encrypt(BigInteger m) {
		return FastExponentiation2(m, e, n);
	}

	private BigInteger Decrypt(BigInteger c) {
		return FastExponentiation2(c, d, n);
	}

	public String EncryptMessage(String message) {
		// Encrypt each character of the message
		StringBuilder encryptedMessage = new StringBuilder();
		for (int i = 0; i < message.length(); i++) {
			encryptedMessage.append(Encrypt(BigInteger.valueOf(message.charAt(i))).toString());
			if (i < message.length() - 1) {
				encryptedMessage.append(",");
			}
		}
		return encryptedMessage.toString();
	}

	public String DecryptMessage(String message) {
		// Decrypt each character of the message
		StringBuilder decryptedMessage = new StringBuilder();
		String[] encryptedMessage = message.split(",");
		for (int i = 0; i < encryptedMessage.length; i++) {
			decryptedMessage.append((char) Decrypt(new BigInteger(encryptedMessage[i])).intValue());
		}
		return decryptedMessage.toString();
	}

	/*
	 * Writing and Reading from files
	 */

	public void ReadPublicKeyFromFile(String filename) {
		String[] pkArray = ReadKeysFromFile(filename);
		n = new BigInteger(pkArray[0]);
		e = new BigInteger(pkArray[1]);
	}

	public void ReadSecretKeyFromFile(String filename) {
		String[] skArray = ReadKeysFromFile(filename);
		n = new BigInteger(skArray[0]);
		d = new BigInteger(skArray[1]);
	}

	// Reads a key from a file and returns an array
	private String[] ReadKeysFromFile(String filename) {
		String[] array = null;
		try {
			String key = Files.readString(Paths.get(filename), StandardCharsets.US_ASCII);
			array = key.replace("(", "")
					.replace(")", "")
					.split(",");
		} catch (Exception e) {
			System.out.println("Error reading file");
		}
		return array;
	}

	public void WritePublicKeyToFile(String filename) {
		WriteToFile(filename, "(" + n.toString() + "," + e.toString() + ")");
	}

	public void WriteSecretKeyToFile(String filename) {
		WriteToFile(filename, "(" + n.toString() + "," + d.toString() + ")");
	}

	public void WriteToFile(String filename, String content) {
		try {
			Files.write(Paths.get(filename), content.getBytes());
		} catch (Exception e) {
			System.out.println("Error writing file");
		}
	}

	public String ReadFromFile(String filename) {
		try {
			return Files.readString(Paths.get(filename), StandardCharsets.US_ASCII);
		} catch (Exception e) {
			System.out.println("Error reading file");
		}
		return null;
	}

	public String DecryptFromFile(String filename) {
		String encryptedMessage = null;
		try {
			encryptedMessage = ReadFromFile(filename);
			return DecryptMessage(encryptedMessage);
		} catch (Exception e) {
			System.out.println("Error reading file");
		}
		return null;
	}

	public void EncryptToFile(String message, String filename) {
		String encryptedMessage = EncryptMessage(message);
		try {
			WriteToFile(filename, encryptedMessage);
		} catch (Exception e) {
			System.out.println("Error writing file");
		}
	}
}