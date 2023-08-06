# RSA stream  
c = stream ^ q より stream = c ^ q  
<img src="https://latex.codecogs.com/gif.latex?\gcd(65537,&space;65539)&space;=&space;1"/> であるから  
<img src="https://latex.codecogs.com/gif.latex?c_1^x&space;c_2^y&space;\equiv&space;m^{65537x&plus;65539y}&space;\equiv&space;m&space;\mod&space;n"/>    
flag: `ACSC{changing_e_is_too_bad_idea_1119332842ed9c60c9917165c57dbd7072b016d5b683b67aba6a648456db189c}`  
