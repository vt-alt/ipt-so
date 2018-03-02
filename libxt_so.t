RUN -m so --so-level 0 ; FAIL
RUN -m so --so-level 1 --so-match-all ; OK
RUN -m so --so-level 1 --so-mismatch  ; OK
RUN -m so --so-level 1 ! --so-match-all ; OK -m so --so-level 1 --so-mismatch
RUN -m so --so-level 255 --so-mismatch  ; OK
RUN -m so --so-level 256 --so-mismatch  ; FAIL
RUN -m so ! --so-level 1 --so-mismatch  ; OK
RUN -m so --so-level 0,1,2,3 --so-mismatch  ; OK
RUN -m so   --so-categ 0 --so-match-all ; OK
RUN -m so ! --so-categ 0 --so-match-all ; OK
RUN -m so --so-categ 1 --so-match-all  ; OK
RUN -m so --so-categ 64 --so-match-all ; OK
RUN -m so --so-categ 65 --so-match-all ; FAIL
RUN -m so --so-categ 1,1 --so-match-all ; FAIL
RUN -m so --so-categ 1 --so-categ 2 --so-match-all ; FAIL
RUN -m so --so-categ 0,1 --so-match-all ; FAIL
RUN -m so --so-categ 1,2 --so-match-all ; OK
RUN -m so --so-categ 0x00 --so-match-all ; OK -m so --so-categ 0 --so-match-all
RUN -m so --so-categ 0x01 --so-match-all ; OK -m so --so-categ 1 --so-match-all
RUN -m so --so-categ 0x02 --so-match-all ; OK -m so --so-categ 2 --so-match-all
RUN -m so --so-categ 0x03 --so-match-all ; OK -m so --so-categ 1,2 --so-match-all
RUN -m so --so-categ 0x04 --so-match-all ; OK -m so --so-categ 3 --so-match-all
RUN -m so --so-level 1 --so-categ 1 --so-match-all ; OK
RUN -m so ! --so-level 1 ! --so-categ 1 --so-match-all ; OK
RUN -m so --so-proto cipso --so-match-all ; OK
RUN -m so --so-proto astra --so-match-all ; OK
RUN -m so --so-proto unlbl --so-match-all ; OK
RUN -m so ! --so-proto cipso --so-match-all ; OK -m so --so-proto unlbl,astra --so-match-all
RUN -m so   --so-proto any --so-match-all ; OK -m so --so-match-all
RUN -m so ! --so-proto any --so-match-all ; FAIL
RUN -m so --so-proto cipso,astra,unlbl --so-match-all ; OK -m so --so-match-all
RUN -m so ! --so-proto unlbl --so-match-all ; OK -m so --so-proto cipso,astra --so-match-all
RUN -m so ! --so-proto cipso,astra,unlbl --so-match-all ; FAIL
RUN -m so   --so-proto cipso --so-doi 1 --so-match-all ; OK
RUN -m so ! --so-proto cipso --so-doi 1 --so-match-all ; FAIL
