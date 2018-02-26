# Селектор меток безопасности для iptables

Данный модуль предоставляет iptables селектор (match) `so`, который позволяет
выделять пакеты содержащих метки безопасности протоколов CIPSO и RFC 1108 (в
модификации Astra Linux SE).

Пример использования:

    # iptables -t security -I INPUT  -i eth0 -m so --so-level 1 --so-categ 2 --so-mismatch -j DROP
    # iptables -t security -I OUTPUT -o eth0 -m so --so-level 1 --so-categ 2 --so-mismatch -j DROP

Данная конфигурация запрещает входящую и исходящую передачу пакетов через
интерфейс eth0, если они не маркированы уровнем 1 и категорией 2.

Параметры:

  --so-proto cipso,astra,unlbl
     выбирает протоколы cipso, astra, unlbl (не маркированый).
     Протоколы выбираются как логическое ИЛИ. Для работы unlbl так же следует
     разрешить уровень 0 без выбора категорий. Однако, уровень 0 может работать
     без unlbl, если требуется, чтоб уровень 0 передавался только в метках.

  --so-level 0..255[,...]
     выбирает уровни доступа (логическое ИЛИ). Уровень 0 (без категории), кроме
     метки с уровнем 0 так же может передаваться как unlbl пакеты.

  --so-categ 0|1..64[,...]
     выбирает категории (логическое И) по их числовому коду, код 0 означет 'без
     категории' и не совместим с категориями 1..64 (нумерация категорий с 1).
     Следует понимать, что наличие категорий, кроме 0, запрещает не
     маркированные пакеты.

  --so-doi <1..MAX>
     DOI для CIPSO. Эта опция относится только к протоколу CIPSO, не
     ограничивая наличие других протоколов. Поддерживается только tag type 1,
     другие тэги будут обрабатываться как parameter problem (пакеты дропаться).

  --so-match-all
     передать все удовлетворяющие параметрам пакеты в таргет.
  --so-mismatch
     передать все не удовлетворяющие параметрам пакеты в таргет.

     Селектор выбирает пакеты соответственно логическому И опций --so-proto,
     --so-level, и --so-categ. Если необходимо запрещать пакеты, то следует
     указать опцию --so-mismatch, тогда в соответствующий таргет (например,
     DROP или REJECT) будут попадать все пакеты не удовлетворяющие параметрам
     Если правилом нужно не запрещать пакеты, а пропускать, то следует указать
     опцию --so-match-all, тогда в iptables таргет (ACCEPT или RETURN) попадут
     все пакеты удовлетворяющие правилам. Однако, в этом случае, следует
     обратить внимание на то, что после ACCEPT или RETURN следующие правила не
     будут обрабатываться. Поэтому, обычно, целесообращнее использовать
     параметр --so-mismatch совместно с `-j DROP`.


* **Домашняя страница**: <https://github.com/vt-alt/ipt-so>

* **Сообщить об ошибке**: <https://bugzilla.altlinux.org>

* **Автор**: vt @ basealt.ru, (c) 2018.

* **Лицензия**: GPL-2.0

