import cpp

from Macro m
where m.getName() in ["ntohs", "ntohll", "ntohs"]
select m, "macro found"
