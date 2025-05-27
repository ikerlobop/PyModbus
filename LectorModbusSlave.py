from tkinter import *
from tkinter import messagebox
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
import scapy.all as scapy


def log_event(text_widget, message):
    text_widget.insert(END, message + "\n")
    text_widget.see(END)


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


def scan_modbus_devices(start_entry, end_entry, subnet_entry, log_text):
    subnet = subnet_entry.get().strip()

    if not subnet or not subnet.endswith("."):
        messagebox.showerror("Error", "La subred debe terminar en punto, por ejemplo: 192.168.0.")
        return

    try:
        start = int(start_entry.get())
        end = int(end_entry.get())

        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            raise ValueError

    except ValueError:
        messagebox.showerror("Error", "Introduce un rango válido (0-255).")
        return

    for i in range(start, end + 1):
        ip_address = subnet + str(i)
        log_event(log_text, f"\nEscaneando {ip_address}...")

        mac_address = get_mac_address(ip_address)
        if mac_address:
            log_event(log_text, f"MAC encontrada: {mac_address}")
        else:
            log_event(log_text, "No se encontró MAC (el host podría no estar activo).")

        client = ModbusTcpClient(ip_address)
        try:
            if not client.connect():
                log_event(log_text, "No se pudo establecer conexión Modbus.")
                continue

            result = client.read_holding_registers(address=0, count=1, slave=1)

            if result.isError():
                log_event(log_text, "No se detectó dispositivo Modbus.")
                continue

            log_event(log_text, "Dispositivo Modbus encontrado.")
            log_event(log_text, f"ID del esclavo: {result.registers[0]}")

            additional = client.read_holding_registers(address=0, count=10, slave=1)
            if not additional.isError():
                log_event(log_text, f"Datos adicionales: {additional.registers}")
            else:
                log_event(log_text, "Error al leer registros adicionales.")

        except ModbusException as e:
            log_event(log_text, f"Error Modbus en {ip_address}: {e}")

        except Exception as e:
            log_event(log_text, f"Error inesperado: {e}")

        finally:
            client.close()

    messagebox.showinfo("Escaneo finalizado", "Escaneo de dispositivos Modbus completado.")


def main():
    root = Tk()
    root.title("Escaneo de dispositivos Modbus")

    frame = Frame(root)
    frame.pack(padx=10, pady=10)

    Label(frame, text="Subred:").grid(row=0, column=0, padx=5, pady=5)
    subnet_entry = Entry(frame)
    subnet_entry.grid(row=0, column=1, padx=5, pady=5)
    subnet_entry.insert(0, "192.168.0.")

    Label(frame, text="Inicio del rango:").grid(row=1, column=0, padx=5, pady=5)
    start_entry = Entry(frame)
    start_entry.grid(row=1, column=1, padx=5, pady=5)

    Label(frame, text="Fin del rango:").grid(row=2, column=0, padx=5, pady=5)
    end_entry = Entry(frame)
    end_entry.grid(row=2, column=1, padx=5, pady=5)

    log_text = Text(frame, width=60, height=20)
    log_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    Button(frame, text="Iniciar escaneo",
           command=lambda: scan_modbus_devices(start_entry, end_entry, subnet_entry, log_text)).grid(row=4, columnspan=2, pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
