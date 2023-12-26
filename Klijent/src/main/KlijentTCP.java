package main;

import java.io.*;
import java.net.*;

public class KlijentTCP {
	private static final int SERVER_PORT = 8080;
	private static final String SERVER_IP = "localhost";
	private static int logStatus = 0;
	private static String USERNAME = "";

	public static void main(String[] args) {
		try {
			Socket socket = new Socket(SERVER_IP, SERVER_PORT);

			BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream())); // Cita podatke
																										// sa servera
			PrintWriter writer = new PrintWriter(socket.getOutputStream(), true); // Salje podatke serveru
			BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in)); // Cita unos klijenta

			String serverskaPoruka;
			// Prikazuje se serverska poruka

			String izbor = "";
			// Odgovor klijenta se salje i prikazuje na serveru

			while (!("0".equals(izbor))) {

				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);
				serverskaPoruka = reader.readLine();
				System.out.println(serverskaPoruka);

				izbor = consoleReader.readLine();
				writer.println(izbor);

				if ("1".equals(izbor)) {
					writer.println(logStatus);
					writer.println(USERNAME);
					if (logStatus == 0) {
						System.out.println(
								"Unesite svoje lične podatke u formatu [ime, prezime, adresa, broj kartice, CVV broj, iznos]:");
						String licniPodaci = consoleReader.readLine();
						writer.println(licniPodaci);
						String odgovor = reader.readLine();
						System.out.println(odgovor);
					} else {
						System.out.println("Unesite svoje lične podatke u formatu [adresa, CVV broj, iznos]:");
						String licniPodaci = consoleReader.readLine();
						writer.println(licniPodaci);
						String odgovor = reader.readLine();
						System.out.println(odgovor);
					}
				}

				else if ("2".equals(izbor)) {
					String odgovor = reader.readLine();
					System.out.println(odgovor);
				}

				else if ("3".equals(izbor)) {
					writer.println(logStatus);
					if (logStatus == 1) {
						String odgovor = reader.readLine();
						System.out.println(odgovor);
					} else {
					System.out.println("Unesite username koji zelite:");
					String username = consoleReader.readLine();
					writer.println(username);
					System.out.println("Unesite password koji zelite:");
					String password = consoleReader.readLine();
					writer.println(password);
					System.out.println("Unesite Vase ime:");
					String ime = consoleReader.readLine();
					writer.println(ime);
					System.out.println("Unesite Vase prezime:");
					String prezime = consoleReader.readLine();
					writer.println(prezime);
					System.out.println("Unesite Vas mail:");
					String mail = consoleReader.readLine();
					writer.println(mail);
					System.out.println("Unesite Vas JMBG:");
					String jmbg = consoleReader.readLine();
					writer.println(jmbg);
					System.out.println("Unesite broj kartice:");
					String kartica = consoleReader.readLine();
					writer.println(kartica);
					System.out.println("Unesite CVV broj:");
					String cvv = consoleReader.readLine();
					writer.println(cvv);
					String odgovor = reader.readLine();
					System.out.println(odgovor);
					}
				}

				else if ("4".equals(izbor)) {
					writer.println(logStatus);
					if (logStatus == 1) {
						String odgovor = reader.readLine();
						System.out.println(odgovor);
						//Slucaj da je korisnik vec ulogovan
						
					} else {
						System.out.println("Unesite Vas username:");
						String username = consoleReader.readLine();
						writer.println(username);
						System.out.println("Unesite Vas password:");
						String password = consoleReader.readLine();
						writer.println(password);
						logStatus = Integer.parseInt(reader.readLine());
						if(logStatus == 0) {
							System.out.println("Prijava neuspesna, probajte ponovo.");
						} else {
							System.out.println("Prijava je uspesna, dobrodosli " + username + "!");
						}
						
						USERNAME = username;
						//Static promenljiva USERNAME se koristi kako bi se "zapamtilo" na kom nalogu je korisnik
					}
				} else if ("5".equals(izbor)) {
					writer.println(logStatus);
					if(logStatus == 1) {
						int brIteracija = Integer.parseInt(reader.readLine());
						String odgovor;
						for(int i = 1; i <= brIteracija; i++) {
							odgovor = reader.readLine();
							System.out.println("Transakcija " + i + ": " + odgovor);
						}
					} else {
						String odgovor = reader.readLine();
						System.out.println(odgovor);
					}
					
				}

				else {
					serverskaPoruka = reader.readLine();
					System.out.println(serverskaPoruka);
				}
			}

			socket.close();
			reader.close();
			writer.close();
			consoleReader.close();
			// Zatvaranje svih otvorenih tokova

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
