from tkinter import *
from tkinter import messagebox
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException
import scapy.all as scapy


def log_event(text_widget, message):
    text_widget.insert(END, message + "\n")
    text_widget.see(END)  # Hace scroll automáticamente para mostrar el mensaje más reciente


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None


def scan_modbus_devices(start, end, subnet_entry, log_text):
    subnet = subnet_entry.get()

    if not subnet.strip():
        messagebox.showerror("Error", "Por favor, introduce una subred válida.")
        return

    if not subnet.endswith("."):
        messagebox.showerror("Error", "La subred debe terminar con un punto (por ejemplo, 192.168.2.).")
        return

    try:
        start_address = int(start.get())
        end_address = int(end.get())

        for i in range(start_address, end_address + 1):
            ip_address = subnet + str(i)
            client = ModbusTcpClient(ip_address)
            mac_address = get_mac_address(ip_address)

            if mac_address:
                log_event(log_text, f"Dispositivo en {ip_address} tiene la dirección MAC: {mac_address}")
            else:
                log_event(log_text, f"No se pudo obtener la dirección MAC del dispositivo en {ip_address}")

            try:
                connection = client.connect()
                result = client.read_holding_registers(0, 1, unit=1)

                if result.isError():
                    log_event(log_text, f"No se encontró dispositivo en {ip_address}")
                    continue

                log_event(log_text, f"Dispositivo Modbus encontrado en {ip_address}")
                slave_id = result.registers[0]
                log_event(log_text, f"Número de identificación del esclavo: {slave_id}")

                additional_result = client.read_holding_registers(0, 10, unit=1)
                log_event(log_text, f"Datos adicionales del esclavo en {ip_address}: {additional_result.registers}")

                client.close()

            except ConnectionException as e:
                if "10051" in str(e):  # WinError 10051: Se ha intentado una operación de socket en una red no accesible
                    log_event(log_text, f"No se pudo conectar a {ip_address}: La red no es accesible.")
                else:
                    log_event(log_text, f"No se pudo conectar a {ip_address}: {e}")

        messagebox.showinfo("Escaneo completado", "El escaneo de dispositivos Modbus ha finalizado.")

    except ValueError:
        messagebox.showerror("Error", "Por favor, introduce números válidos para el inicio y el final del rango.")


def main():
    root = Tk()
    root.title("Escaneo de dispositivos Modbus")

    frame = Frame(root)
    frame.pack(padx=10, pady=10)

    subnet_label = Label(frame, text="Subred:")
    subnet_label.grid(row=0, column=0, padx=5, pady=5)

    subnet_entry = Entry(frame)
    subnet_entry.grid(row=0, column=1, padx=5, pady=5)
    subnet_entry.insert(0, "0.0.0.")  # Valor predeterminado para la subred

    start_label = Label(frame, text="Inicio del rango:")
    start_label.grid(row=1, column=0, padx=5, pady=5)

    start_entry = Entry(frame)
    start_entry.grid(row=1, column=1, padx=5, pady=5)

    end_label = Label(frame, text="Fin del rango:")
    end_label.grid(row=2, column=0, padx=5, pady=5)

    end_entry = Entry(frame)
    end_entry.grid(row=2, column=1, padx=5, pady=5)

    log_text = Text(frame, width=60, height=20)
    log_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    scan_button = Button(frame, text="Iniciar escaneo",
                         command=lambda: scan_modbus_devices(start_entry, end_entry, subnet_entry, log_text))
    scan_button.grid(row=4, columnspan=2, padx=5, pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
