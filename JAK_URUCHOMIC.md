# W jaki sposób uruchomić ten projekt?

## **1. Po pierwsze trzeba stowrzyć środowiso wirtualne pythona**

### należy przejść do folderu, w którym chcemy stworzyć środowisko wirtualne pythona i użyć nasępującej komendy:

> python -m venv env

### utworzy to środowisko wirtualne o nazwie ```env```

<br>

## **2. Należy teraz uruchomić to środowisko wirtualne**

### aby uruchomić to środowisko wirtualne należy wykonać poniższą komendę (znajdując się w tym samym folderze co środowisko wirtualne)

- jeśli jesteśmy na windowsie:
> .\env\Scripts\activate

- jeśli jesteśmy na linuksie/MacOS
> source ./bin/activate

### teraz powinniśmy zauważyć znak zachęty ```(env)``` w konsoli

<br>

## **3. Do tego folderu w którym utworzyliśmy środowisko wirtualne należy przekopiować plik ```requirements.txt``` który znajduje się w folderze ```src``` tego projektu**


<br>


## **4. Teraz należy zainstalować wszystkie wymagane zależności**

### aby zainstalować zależności trzeba teraz wykonać następującą komende (znajdując sie w folderze ze środowiskiem env oraz plikiem requirements.txt)

> python -m pip install -r requirements.txt

<br>

## **5. Teraz należy uruchomić skrypt ```serwer.py```**
### uruchamiamy serwer następująca komendą:

> python src/serwer.py

### **Zawsze trzeba najpierw uruchomić serwer**

<br>

## **6. Uruchamiamy _dowolną_ ilość peerów**
### uruchamiamy peera następująca komendą

> python src/peer.py

### powtarzamy ten krok wiele razy aby stworzyć sieć P2P
