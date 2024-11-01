"""Functions for time and date operations."""
import datetime
import time

def main():
    """Main function"""
    last_coffee_time = input("När drack du kaffe senast? (ange tid i formatet YYYY-MM-DD HH:MM): ")
    try:
        last_coffee_time = datetime.datetime.strptime(last_coffee_time, '%Y-%m-%d %H:%M')
    except ValueError:
        print("Ogiltigt datumformat. Försök igen.")
        return
    wait_time = input(
        """Hur länge vill du vänta innan du dricker kaffe igen?
(ange tid i timmar och minuter, t.ex. 1:30): """
        )
    try:
        hours, minutes = map(int, wait_time.split(':'))
        current_time = datetime.datetime.now()
        alarm_time = current_time + datetime.timedelta(hours=hours, minutes=minutes)
    except ValueError:
        print("Ogiltigt tidsformat. Försök igen.")
        return

    total_time_since_last_coffee = current_time - last_coffee_time + datetime.timedelta(
        hours=hours, minutes=minutes
        )
    if total_time_since_last_coffee < datetime.timedelta(hours=1):
        print("""Varning:
             Du har angivit mindre än en timme mellan kaffedrickande!
             Var försiktig med koffeinintaget.""")
    print(f"Alarmet är inställt på: {alarm_time.strftime('%Y-%m-%d %H:%M')}")

    while True:
        current_time = datetime.datetime.now()
        if current_time >= alarm_time:
            print("Dags att dricka kaffe igen!")
            break
        time.sleep(30)  # Kollar varje 30:e sekund om det är dags för kaffe.

if __name__ == "__main__":
    main()
