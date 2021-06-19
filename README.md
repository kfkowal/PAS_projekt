# Sieć P2P, szyfrowane wiadomości

## Celem tego projektu była próba zaimplementowania sieci P2P. 

### Aby nadać sens takiej sieci P2P postanowiłem, że będzie ona wykorzystywana do anonimowej, szyfrowanej komunikacji (a przynajmniej wydaje mi się, że jest anonimowa)

<br>
<br>

### Zaimplementowana w tym projekcie sieć P2P jest [nieustruktyzowana](https://en.wikipedia.org/wiki/Peer-to-peer#Unstructured_networks) a do routingu używa [floodingu](https://en.wikipedia.org/wiki/Flooding_(computer_networking)), oznacza to, że każdy z peerów rozsyła każdą otrzymaną wiadomość do wszystkich swoich "sąsiadów" (oprócz tego od którego otrzymał wiadomość, zaimplementowane jest też cache).

### Wiadomości są zaszyfrowane kluczem publicznym, zatem tylko peer, który posiada odpowiadający temu kluczowi publicznemu klucz prywatny będzie w stanie odczytać wiadomość. **Wszystkie inne peery zatem nie wiedzą, od kogo jest dana wiadomość, nie wiedzą do kogo jest dana wiadomość i nie znają też treści tej wiadomości, po prostu rozprowadzają ją po sieci aż może trafi do odpowiedniego peera.**

<br>
<br>

### Istnieje kwestia tego skąd pozyskać dany klucz publiczny, musi istnieć jakiś mechanizm rozprowadzania takich kluczy. W tym projekcie zakładam, że serwer, który jest używany jest zaufany oraz że to na nim są zapisywane klucze tych peerów, które chcą ogłosić swój klucz. Później inne peery mogą z tego serwera pobrać dany klucz i zaszyforwać nim swoją wiadomość (lepsze byłoby jakieś rozprowadzanie kluczy po sieci za pomocą routngu ale postanowiłem, że prawdopodobnie oznaczałoby to dla mnie więcej pracy niż chciałem poświęcić na ten projekt)

<br>
<br>

## **Realistyczny** przykład użycia takiej sieci:

- Załóżmy, że jesteśmy generałem United States Air Force i że posiadamy informacje o kosmitach odwiedzających Ziemię, chcemy podzielić się taką informacją ze światem ale nie chcemy stracić pracy, nie chcemy też "popełniać samobójstwa", postanawiamy więc użyć tej sieci P2P

- upubliczniamy nasz klucz publiczny i przyłączamy do niego wiadomość "Mam informacje o kosmitach odwiedzających Ziemię"

- inne peery w sieci zobaczą to ogłoszenie, ale nie będą miały pojęcia kto je ogłosił, oczywiście nie będą też wiedziały czy można zaufać takiej informacji, to od nich zależy czy się tym zainteresują.

- jeśli jakiś peer zechce skomunikować się z nadawcą tej wiadomości, to stworzy wiadomość, w której zada swoje pytanie o kosmitów i zaszyfruje ją kluczem publicznym generała i rozprowadzi to po sieci. Oprócz tego do wiadomości doda też swój klucz publiczny, tak aby generał, mógł w taki sam sposób odpowiedzieć

- dzięki temu generał i zainteresowany peer mogą wymieniać się informacjami kompletnie anoniowo. Można sobie wyobrazić nieco ulepszoną wersję takiej sieci, gdzie oprócz zwykłych wiadomości mogą się wymieniać plikami, generał mógłby wtedy przesłać tej osobie jakieś fimy ufo.


<br>
<br>

### **Dlaczego projekt o sieciach P2P zawiera serwer?**

- praktyczne każdy inny projekt P2P, o którym można znaleźć informacje zawiera jakąś formę serwera do wspomagania pewnych akcji. Głównie wykorzystywany jest on do tworzenia sieci (każdy peer musi być połączony z co najmniej jednym innym peerem, ale skąd ma znać ip innych peerów? Może istnieć jakiś serwer, który zawiera informacje o innych perach). W tym konkretnym projekcie serwer jest używany do jeszcze innych rzeczy ale to dlatego, że wykonanie tych rzeczy było by dla mnie zbyt pracochłonne. 


### **Wytłumaczenie nazw komend możliwych do użycia w peerach**

- 'sm', oznaczna 'secret message', czyli sekretna wiadomość, operacja ta służy do wysyłania wiadomości
- 'resp', oznacza 'response', czyli odpowiedź, za pomocą tej komendy można odpowiedzieć na otrzymaną wiadomość

- 'list', za pomocą tej komendy można wylistować wszystkie dostępne ogłoszenia (które zawierają klucze publiczne)

- 'help', za pomocą tej komendy uzyskamy informacje jak używać innych komend