package main;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class ServerTCP {
	private static final int PORT = 8080;
	private static Map<String, String> cardDetails = new HashMap<>();
	private static List<Nalog> listaNaloga = new ArrayList<Nalog>();
	private static ArrayList<String> listaTransakcija = new ArrayList<String>();
	private static int iznos = 0;
	// Postavljanje porta kao i mape u kojoj ce se cuvati informacije o karticama

	public static class Nalog {
		String username;
		String password;
		String ime;
		String prezime;
		String jmbg;
		String brojKartice;
		String cvv;
		String mail;
	}

	public static void main(String[] args) {
		try {
			ServerSocket serverSocket = new ServerSocket(PORT);
			System.out.println("Server je uspesno pokrenut..");
			// Inicijalizacija novog server socketa na portu 8080

			cardDetails.put("1111-1111-1111-1111", "111");
			cardDetails.put("2222-2222-2222-2222", "222");
			cardDetails.put("3333-3333-3333-3333", "333");
			cardDetails.put("4444-4444-4444-4444", "444");
			// Ubacivanje predefinisanih kartica u HashMap

			listaNaloga = ucitajNaloge("nalozi.txt");
			listaTransakcija = ucitajTransakcije("transakcije.txt");

			while (true) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Novi klijent je povezan: " + clientSocket.getInetAddress());
				ClientHandler clientHandler = new ClientHandler(clientSocket);
				new Thread(clientHandler).start();
			}

			// Uspostavljanje veze sa klijentom i prikazivanje adrese klijenta koji se
			// povezao kao i kreiranje nove niti na kojoj radi funkcija
			// Client handler nam omogucava da istovremeno postoji vise opsluzivanih
			// korisnika
		} catch (BindException e){
			System.err.println("Server je vec pokrenut na ovom portu.");

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static class ClientHandler implements Runnable {
		private Socket clientSocket;

		public ClientHandler(Socket socket) {
			this.clientSocket = socket;
		}

		@Override
		public void run() {
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

				String izbor = "";
				while (!("0".equals(izbor))) {

					writer.println(
							"==================================================\nUspesno povezivanje! Odaberite opciju: "
							+ "\n1. Uplata sredstava "
							+ "\n2. Pregled ukupno skupljenih sredstava "
							+ "\n3. Registracija "
							+ "\n4. Ulogujte se "
							+ "\n5. Prikazi poslednjih 10 transakcija "
							+ "\n0. Izlaz");

					izbor = reader.readLine();
					int accStatus;

					switch (izbor) {
					case "1":
						izvrsiDonaciju(reader, writer);
						break;
					case "2":
						proveriSredstva(reader, writer);
						break;
					case "3":
						 accStatus = Integer.parseInt(reader.readLine());
						 if(accStatus == 0) {
							 listaNaloga = registracija(reader, writer, listaNaloga);
						 } 
						 else {
							 writer.println("Vec ste ulogovani, ne mozete da se registrujete!");
						 }
						// Proverava da li je korisnik vec ulogovan
						break;
					case "4":
						 accStatus = Integer.parseInt(reader.readLine());
						if(accStatus == 0) {
							String username = reader.readLine();
							String password = reader.readLine();
							int logStatus = logovanje(username, password);
							writer.println(logStatus);
						} else {
							writer.println("Vec ste ulogovani!");
						}
						//Ako je accStatus koji posalje korisnik 0 to znaci da nije ulogovan
						//Onda se pokrece funkcija logovanje i ako je sve ok menja logStatus korisnika iz 0 u 1
						
						
						break;
					case "5":
						accStatus = Integer.parseInt(reader.readLine());
						if(accStatus == 0) {
							writer.println("Za ovu opciju morate biti ulogovani!");
						} else {
						ispisi10Transakcija(reader, writer);
						}
						break;
					case "0":
						writer.println("Hvala na izdvojenom vremenu.");
						clientSocket.close();

						break;
					default:
						writer.println("Nepostojeci unos. Pokusajte ponovo.");
						break;
					}
				}

				clientSocket.close();

				// Client handler daje korisniku da bira izmedju 3 opcije, korisnikov izbor se
				// cuva i ubacuje u switch, na taj nacin se pokrece 1 od 3 funkcije

			} catch (IOException e) {
				System.err.println("Klijent je prekinuo vezu.");
			}
		}

	}

	public static void izvrsiDonaciju(BufferedReader reader, PrintWriter writer) throws IOException {

		int logStatus = Integer.parseInt(reader.readLine());
		String username = reader.readLine();
		Nalog nalog = nadjiNalog(username);

		String licniPodaci;
		licniPodaci = reader.readLine();

		String ime, prezime, adresa, brojKartice, cvv;
		int kolicinaNovca;

		if (logStatus == 0) {

			if (!(licniPodaci.matches("^\\s*[^,]+\\s*,\\s*[^,]+\\s*,\\s*[^,]+\\s*,\\s*[^,]+\\s*,\\s*[^,]+\\s*,\\s*\\d+\\s*$"))) {
				writer.println("Informacije nisu unete u dobrom formatu. Pokusajte ponovo.");
				//Proverava da li unet string ima odredjeni format
				
				return;
			}
			String[] podaciNiz = licniPodaci.split(",");

			ime = podaciNiz[0].trim();
			prezime = podaciNiz[1].trim();
			adresa = podaciNiz[2].trim();
			brojKartice = podaciNiz[3].trim();
			cvv = podaciNiz[4].trim();
			kolicinaNovca = Integer.parseInt(podaciNiz[5].trim());
			iznos = procitajIznos() + kolicinaNovca;

		} else {

			if (!(licniPodaci.matches("\\s*^[^,]+\\s*,\\s*[^,]+\\s*,\\s*\\d+\\s*$"))) {
				writer.println("Informacije nisu unete u dobrom formatu. Pokusajte ponovo.");
				return;
			}
			String[] podaciNiz = licniPodaci.split(",");

			ime = nalog.ime;
			prezime = nalog.prezime;
			adresa = podaciNiz[0].trim();
			brojKartice = nalog.brojKartice;
			cvv = podaciNiz[1].trim();
			kolicinaNovca = Integer.parseInt(podaciNiz[2].trim());
			iznos = procitajIznos() + kolicinaNovca;
		}
		//Postoje dve razlicite vrste unosa za ulogovanog i neulogovanog korisnika
		// Korisnikov unos se smesta u string licniPodaci i odvaja se u posebne
		// Stringove sa kriterijumom ',' za odvajanje

		if (kolicinaNovca > 200) {
			if (proveriKarticu(brojKartice, cvv)) {
				writer.println("Uplata uspešna. Hvala Vam na velikodusnosti.");
				System.out.println("Prosla je uplata od korisnika " + ime + " " + prezime);
				zabeleziTransakciju(ime, prezime, adresa, brojKartice, kolicinaNovca);
				zabeleziKlijenta(ime, prezime, adresa, brojKartice, kolicinaNovca);
				upisiIznos(iznos);
				//U zasebne fajlove se belezi transakcija, iznos i racun za klijenta.
				
			} else {
				writer.println("Neispravna kartica ili CVV broj. Uplata nije izvrsena.");
				System.out.println("Uplata nije uspesna zbog neispravnosti unetih podataka.");
			}
		} else {
			writer.println("Nedovoljan unos.");
			System.out.println("Uplata nije uspesna zbog nedovoljnog unosa.");
		}

	}

	public static boolean proveriKarticu(String brojKartice, String cvv) {
		if (cardDetails.containsKey(brojKartice)) {
			String predefinisaniCvv = cardDetails.get(brojKartice);
			if (cvv.equals(predefinisaniCvv)) {
				return true;
			} else {
				return false;
			}
		}
		return false;

		// U ovoj funkciji se na osnovu unetog broja kartice i cvv proverava da li u
		// HashMap postoji unos sa kljucem koji je jednak unetom broju kartice, ako
		// postoji onda proverava da li se CVV u HashMapu koji odgovara broju kartice
		// podudara sa CVV koji je uneo korisnik
	}

	public static void proveriSredstva(BufferedReader reader, PrintWriter writer) throws IOException {
		writer.println("Ukupna skupljena sredstva su: " + procitajIznos());
	}

	public static void zabeleziTransakciju(String ime, String prezime, String adresa, String brojKartice, double iznos)
			throws IOException {
		String vreme = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		String podaciTransakcije = String.format("%s, %s, %s, %s, %s, %.2f", ime, prezime, adresa, brojKartice, vreme,
				iznos);

		File file = new File("transakcije.txt");
		if (!file.exists()) {
			file.createNewFile();
		}
		// Provera da li fajl postoji, ako ne postoji kreira ga

		BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
		writer.write(podaciTransakcije);
		writer.newLine();
		writer.close();
	}

	public static void zabeleziKlijenta(String ime, String prezime, String adresa, String brojKartice, double iznos)
			throws IOException {
		String vreme = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		Random randomBroj = new Random();
		String randomString = Integer.toString(randomBroj.nextInt(1000000));
		String podaciTransakcije = String.format("%s, %s, %s, %s, %s, %.2f", ime, prezime, adresa, brojKartice, vreme,
				iznos);
		File file = new File(ime + randomString + ".txt");
		//Daje fajlu randomizovano ime sa veoma malom sansom poklapanja.
		
		if (!file.exists()) {
			file.createNewFile();
		}
		// Provera da li fajl postoji, ako ne postoji kreira ga

		BufferedWriter writer = new BufferedWriter(new FileWriter(file, false));
		writer.write(podaciTransakcije);
		writer.newLine();
		writer.close();
	}

	public static void upisiIznos(int iznos) throws IOException {
		String iznosTxt = String.format("%d", iznos);
		File file = new File("iznos.txt");
		if (!file.exists()) {
			file.createNewFile();
		}
		// Provera da li fajl postoji, ako ne postoji kreira ga

		BufferedWriter writer = new BufferedWriter(new FileWriter(file, false));
		writer.write(iznosTxt);
		writer.close();
	}

	public static int procitajIznos() {
		int iznos = 0;

		File file = new File("iznos.txt");
		if (!file.exists()) {
			return iznos;
		}
		//Ako fajl ne postoji, vraca nula posto je pocetna vrednost iznosa nula.

		try (BufferedReader reader = new BufferedReader(new FileReader("iznos.txt"))) {
			String red = reader.readLine();
			if (red != null && !red.isEmpty()) {
				try {
					iznos = Integer.parseInt(red);
				} catch (NumberFormatException e) {
					System.err.println("Nije moguće parsirati vrednost kao integer.");
				}
				// Pokušavamo parsirati vrednost procitanu iz fajla kao double
				
			}
		} catch (IOException e) {
			System.err.println("Greška prilikom čitanja fajla: " + e.getMessage());
		}

		return iznos;
	}

	public static List<Nalog> ucitajNaloge(String imeFajla) {
		List<Nalog> listaNaloga = new ArrayList<Nalog>();

		String podaciNaloga;
		String podaciNiz[];
		File file = new File(imeFajla);
		if (!file.exists()) {
			return listaNaloga;
		}
		//Ako fajl ne postoji, vraca praznu listu posto joj je pocetna vrednost null.

		try {
			BufferedReader reader = new BufferedReader(new FileReader(imeFajla));
			while ((podaciNaloga = reader.readLine()) != null) {

				// Proverava da li je reader procitao prazan red ili fajl ne postoji, ako je to
				// tacno prekida petlju.
				// U suprotnom je vrti dok ne dodje do kraja

				Nalog noviNalog = new Nalog();
				podaciNiz = podaciNaloga.split(",");
				noviNalog.username = podaciNiz[0].trim();
				noviNalog.password = podaciNiz[1].trim();
				noviNalog.ime = podaciNiz[2].trim();
				noviNalog.prezime = podaciNiz[3].trim();
				noviNalog.jmbg = podaciNiz[4].trim();
				noviNalog.brojKartice = podaciNiz[5].trim();
				noviNalog.cvv = podaciNiz[6].trim();
				noviNalog.mail = podaciNiz[7].trim();

				listaNaloga.add(noviNalog);
				// Podaci se stavljaju u nalog i nakon toga se on dodaje u listu naloga
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return listaNaloga;
	}

	public static ArrayList<String> ucitajTransakcije(String imeFajla) {

		String podaciTransakcija;
		String podaciNiz[];
		File file = new File(imeFajla);
		if (!file.exists()) {
			return listaTransakcija;
		}
		//Ako fajl ne postoji, vraca praznu listu posto joj je pocetna vrednost null.

		try {
			BufferedReader reader = new BufferedReader(new FileReader(imeFajla));
			while ((podaciTransakcija = reader.readLine()) != null) {

				// Proverava da li je reader procitao prazan red ili fajl ne postoji, ako je to
				// tacno prekida petlju.
				// U suprotnom je vrti dok ne dodje do kraja

				listaTransakcija.add(0, podaciTransakcija);
				//Podaci o transakcijama se dodaju na prvo mesto liste
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return listaTransakcija;
	}
	
	public static void ispisi10Transakcija(BufferedReader reader, PrintWriter writer) {
		
		int brElemenata;
		if(listaTransakcija.size() < 10) {
			 brElemenata = listaTransakcija.size();
		} else {
			 brElemenata = 10;
		}
		//U slucaju da postoji manje od 10 elemenata, prikazace se taj broj
		//Ako postoji 10 ili vise elemenata, uvek ce se prikazati samo 10
		
		writer.println(brElemenata);
		for(int i = 0; i < brElemenata; i++) {
				writer.println(listaTransakcija.get(i));
				
		}
		return;
	}
	
	
	public static void sacuvajNalog(Nalog nalog, String imeFajla) throws IOException {

		String podaciNaloga = nalog.username + "," + nalog.password + "," + nalog.ime + "," + nalog.prezime + ","
				+ nalog.jmbg + "," + nalog.brojKartice + "," + nalog.cvv + "," + nalog.mail;
		//Cuva sve podatke o nalogu u jednom stringu

		File file = new File(imeFajla);
		if (!file.exists()) {
			file.createNewFile();
		}
		// Provera da li fajl postoji, ako ne postoji kreira ga

		BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
		writer.write(podaciNaloga);
		writer.newLine();
		writer.close();
		//U txt fajl se u jednoj liniji ispisuju informacije o nalogu
		
	}

	public static List<Nalog> registracija(BufferedReader reader, PrintWriter writer, List<Nalog> listaNaloga)
			throws IOException {
		Nalog noviNalog = new Nalog();
		noviNalog.username = reader.readLine();
		noviNalog.password = reader.readLine();
		noviNalog.ime = reader.readLine();
		noviNalog.prezime = reader.readLine();
		noviNalog.mail = reader.readLine();
		noviNalog.jmbg = reader.readLine();
		noviNalog.brojKartice = reader.readLine();
		noviNalog.cvv = reader.readLine();
		//Stavlja info u novi nalog
		
		if (proveriKarticu(noviNalog.brojKartice, noviNalog.cvv) && dostupnostUsername(noviNalog.username)) {
			listaNaloga.add(noviNalog);
			sacuvajNalog(noviNalog, "nalozi.txt");
			writer.println("Registracija korisnika je uspesna!");
			return listaNaloga;
		}
		//Proverava validnost kartice i da li je username vec iskoriscen
		//Ako je sve ok, stavlja novi nalog u listu naloga i cuva novi nalog u bazu podataka
		
		writer.println("Registracija nije uspesna.");
		return listaNaloga;

	}

	public static int logovanje(String username, String password) {
		if (!dostupnostUsername(username)) {
			for (Nalog nalog : listaNaloga) {
				if (nalog.username.equals(username)) {
					if (nalog.password.equals(password)) {
						return 1;
					}
				}
			}
		}
		//Funkcija proverava da li uopste postoji nalog sa takvim username, ako postoji nalazi 
		//ga i gleda da li odgovara ta sifra, ako odgovara vraca 1
		
		return 0;
	}

	public static Nalog nadjiNalog(String username) {
		for (Nalog nalog : listaNaloga) {
			if (nalog.username.equals(username)) {
				return nalog;
			}
		}
		//Prolazi kroz celu listu naloga i vraca nalog sa istim username koji je unet
		
		return null;
	}

	public static boolean dostupnostUsername(String username) {
		for (Nalog nalog : listaNaloga) {
			if (nalog.username.equals(username)) {
				return false;
			}
		}
		//Prolazi kroz celu listu naloga i gleda da li postoji neki koji vec ima taj username
		
		return true;
	}
}
