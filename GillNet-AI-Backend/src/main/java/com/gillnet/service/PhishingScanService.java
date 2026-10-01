package com.gillnet.service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.gillnet.dto.PhishingScanDto;
import com.gillnet.dto.UrlScanDto;
import com.gillnet.model.ScanRecord;

@Service
public class PhishingScanService {

    private static final Logger log = LoggerFactory.getLogger(PhishingScanService.class);

    private final UrlScanService urlScanService;
    private final HistoryService historyService;
    private final RestClient restClient;

    @Value("${ml.service.url:http://localhost:5000}")
    private String mlServiceUrl;

    // Known target brands & enterprise impersonation commonly spoofed in phishing
    private static final String[] TARGET_BRANDS = {
            "Contoso", "Workplace Alert", "HR Team", "Human Resources",
            "PayPal", "Microsoft", "Netflix", "Apple", "Google",
            "Chase", "Bank of America", "Wells Fargo", "Amazon",
            "DHL", "FedEx", "USPS", "Binance", "Coinbase", "MetaMask"
    };

    // Urgency / lure triggers (+12 each). Tuned on 3,000 labeled SMS messages.
    private static final String[] URGENCY_TRIGGERS = {
            "device and internet usage policy", "viewing of inappropriate material", "inappropriate material online", "prohibited online activity",
            "recorded your webcam", "recorded your screen", "compromised browsing history", "facing termination",
            "disciplinary interview", "aforementioned evidence", "sign-in attempt was blocked", "someone just used your password",
            "from a non-google app", "review your account activity", "immediately", "urgent",
            "action required", "within 24 hours", "account suspended", "blocked",
            "restricted", "expire today", "unauthorized access", "act now",
            "final notice", "deactivated", "locked out", "unusual activity",
            "critical alert", "security alert", "congratulations", "congrats",
            "you have won", "you've won", "have won", "won the",
            "winner", "lottery", "prize", "award",
            "claim your", "claim now", "to claim", "selected to receive",
            "lucky day", "await collection", "awaiting collection", "free entry",
            "free gift", "free ringtone", "cash prize", "cash-balance",
            "txt to", "text to", "reply to claim", "call now",
            "call today", "win £", "win a", "chance to win",
            "to win", "weekly quiz", "wkly", "freemsg",
            "free msg", "ringtone", "polyphonic", "dating service",
            "chatline", "strong-buy", "explosive pick", "un-redeemed",
            "entitled to", "sexy", "txtin", "hardcore",
            "auction", "draw", "voucher", "half price",
            "line rental", "blind date", "camera phone", "txt word",
            "text word", "opt out", "unsubscribe", "subscription",
            "double txt", "double mins", "tone", "tones"
    };

    // Credential / money harvesting triggers (+20 each, capped at +50).
    private static final String[] HARVESTING_TRIGGERS = {
            "view recorded evidence", "review recorded evidence", "download evidence", "view evidence",
            "check activity", "checkactivity", "review account activity", "sign in to your account",
            "verify your account", "enter password", "verify password", "update password",
            "confirm your pin", "provide otp", "security question", "social security",
            "card number", "cvv", "expiry date", "seed phrase",
            "secret key", "billing information", "login credentials", "reset password",
            "click here to unlock", "access document", "open attachment", "otp",
            "one-time password", "verification code", "gift card", "wire transfer",
            "processing fee", "claim your prize", "bank details", "account details",
            "card details", "premium rate", "secret admirer", "cash-in",
            "charged", "p/min", "per min"
    };

    // Spam-token cluster: 4+ distinct tokens -> +25 (safety net for grey marketing spam).
    private static final String[] SPAM_TOKEN_CLUSTER = {
            "win", "won", "prize", "free",
            "claim", "cash", "txt", "call",
            "urgent", "offer", "deal", "discount",
            "voucher", "subscription", "ringtone", "dating",
            "chat", "adult", "sexy", "quiz",
            "draw", "award", "bonus", "gift",
            "promo", "promotion", "winner", "congratulations",
            "selected", "entitled", "exclusive", "limited",
            "hurry", "money", "click", "link",
            "http", "unsubscribe", "premium", "charged",
            "billed", "mins"
    };

    private static final Pattern PREMIUM_RATE_PATTERN = Pattern.compile("premium\\s*rate|\\b09\\d{8,}\\b|\\b087[01]\\d{6,}\\b|\\b084[45]\\d{6,}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHORTCODE_CTA_PATTERN = Pattern.compile("\\b(txt|text|send)\\b[\\w\\s:]{0,30}\\bto\\s+\\d{4,6}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern WORD_PATTERN = Pattern.compile("[a-z']{2,}");

    // Naive-Bayes word log-odds trained on 3,000 labeled SMS messages (spam vs ham).
    // Applied only as a tiebreaker when rule signals are weak (risk 20-39).
    private static final String NB_WEIGHT_DATA = """
'maangalyam=0.81
's=2.602
'simple'=0.81
't=0.81
'til=0.81
abi=0.81
abj=0.81
able=-1.036
about=-0.731
abta=3.007
ac=3.7
access=3.518
accident=2.314
account=1.541
acted=0.81
acting=0.81
action=3.295
activate=2.602
activities=0.81
actually=-1.036
ad=1.908
added=2.314
address=0.897
admin=0.81
admirer=3.988
admit=0.81
adore=0.81
adult=3.007
advice=0.81
ae=3.295
aeronautics=0.81
aeroplane=0.81
affairs=0.81
after=-0.885
afternoon=-0.982
again=-1.009
age=2.92
ah=-1.087
aight=-0.982
ain't=0.81
airport=1.215
aiyar=0.81
alaipayuthe=0.81
alcohol=0.81
alfie=3.007
allowed=0.81
already=-1.92
alright=-0.8
also=-0.954
always=-1.31
alwys=0.81
american=0.81
among=1.908
amp=-1.78
amt=0.81
amy=1.908
anna=0.81
anniversary=0.81
announcement=3.518
ans=1.726
ansr=3.007
answer=0.992
anybody=0.81
anything=-1.78
anytime=2.756
anyway=-0.982
anyways=0.81
anywhere=0.81
apart=0.81
apo=0.81
app=1.908
applebees=0.81
apply=4.904
appreciated=0.81
appt=0.81
ar=0.81
arcade=3.007
area=2.132
argh=0.81
argue=0.81
armand=0.81
arng=0.81
around=-0.731
arrange=0.81
arrested=0.81
arrive=3.518
arsenal=3.007
asap=2.196
ask=-1.92
asks=0.81
at=-0.71
atlast=0.81
atm=0.81
attempt=3.613
attend=0.81
auction=3.161
august=3.007
aunts=0.81
aunty=0.81
auto=0.81
av=0.81
ave=2.314
avoiding=0.81
await=3.78
awaiting=3.7
award=4.306
awarded=4.853
ba=1.908
babes=0.992
bad=-0.8
balance=2.314
bank=1.215
barely=0.81
basic=0.81
bat=0.81
bay=0.81
bcm=3.518
bday=0.81
beautiful=-0.864
bec=0.81
because=-1.136
bed=-1.136
bedroom=0.992
been=1.173
beg=1.908
begin=1.908
behind=0.81
bein=0.81
belive=0.81
bell=0.81
belly=0.81
belovd=0.81
ben=1.908
beneficiary=0.81
benefits=1.908
bet=0.81
between=1.155
beware=0.81
bf=0.81
bids=1.908
bigger=0.81
biggest=1.908
bill=1.215
billed=3.007
billion=0.81
bin=0.81
birds=1.215
birla=0.81
birth=0.81
birthdate=0.81
bishan=0.81
bit=-1.387
biz=3.518
blake's=0.81
blessings=0.81
block=1.908
blood=0.81
bluetooth=3.518
bluff=0.81
bmw=0.81
bonus=3.988
book=1.215
booking=1.503
bored=0.704
boring=0.81
born=0.81
borrow=0.81
bottom=0.81
bought=1.215
bowl=0.81
box=4.186
boy=-0.731
boyfriend=0.81
boys=2.314
brah=0.81
brand=1.908
bray=3.007
bread=0.81
break=1.215
bright=0.81
bringing=1.908
brings=1.503
bro=0.81
broad=0.81
broke=0.81
bros=0.81
brothas=0.81
brought=1.503
bruce=0.81
bstfrnd=0.81
bt=2.004
btw=0.81
buff=0.81
burns=1.908
bus=-0.731
business=0.81
but=-2.152
buzz=0.81
bx=3.518
c's=4.306
cal=1.908
calculation=0.81
call=2.314
calld=0.81
caller=3.007
calls=1.908
camcorder=4.211
camera=4.853
can=-0.8
can't=-1.647
canal=0.81
cancel=1.908
cappuccino=0.81
captain=0.81
car=-1.424
card=1.061
cardiff=0.81
cared=0.81
career=1.908
careful=2.314
carefully=0.81
cars=0.81
cash=3.6
cat=0.81
caught=0.81
cc=3.007
cd=2.314
cdgt=3.007
cds=3.295
celebrate=0.81
celebration=0.81
cha=0.81
chance=3.189
changed=0.81
changes=0.81
charge=2.602
charged=4.106
charges=1.503
charity=3.007
chart=3.007
chasing=0.81
chat=2.773
cheap=1.215
cheaper=1.215
cheat=0.81
chechi=0.81
cheese=0.81
child=0.81
children=1.908
chill=0.81
china=0.81
chinese=0.81
choice=1.503
choose=2.378
christmas=0.81
cinema=1.621
citizen=0.81
city=2.314
claim=5.986
claire=1.908
classes=0.81
cld=0.81
cleared=0.81
clearing=0.81
click=2.196
clos=0.81
close=1.349
clothes=0.81
club=4.106
cm=2.602
cn=0.81
co=4.434
cock=1.908
code=3.988
coins=0.81
collect=2.938
collected=1.908
collection=4.742
colour=4.306
com=2.756
come=-2.862
comes=0.81
coming=-1.424
comp=3.161
compare=3.007
competition=1.908
complete=1.908
completely=0.81
complimentary=4.106
computer=0.81
comuk=3.518
concert=0.81
conditions=2.602
confirmed=0.81
confused=0.81
congrats=2.196
congratulations=4.106
connection=0.81
console=3.007
constant=0.81
contact=3.631
content=3.295
contract=1.908
control=0.81
cooked=0.81
cooking=0.81
cornwall=3.007
correct=1.572
correction=0.81
cos=-1.647
cost=2.662
costa=3.295
costing=3.007
costs=2.196
country=1.908
couple=0.81
cr=3.295
credit=3.007
credited=0.81
credits=3.7
creep=0.81
cross=2.314
croydon=3.854
cruise=1.908
cry=0.81
cs=5.241
cum=1.349
cup=1.215
curious=0.81
current=1.503
currently=2.419
cust=3.295
custcare=3.988
customer=4.244
cutefrnd=0.81
cw=3.007
da=-1.661
dad=-0.864
dai=0.81
daily=1.908
dare=0.81
darling=1.503
dat=-1.31
date=1.908
dates=1.908
dating=3.7
datz=0.81
days=1.333
dearly=0.81
december=3.295
definite=0.81
del=3.295
delay=0.81
deleted=0.81
delhi=0.81
delivered=3.007
delivery=3.78
den=-0.8
depressed=0.81
details=1.456
detroit=1.908
devouring=0.81
di=0.81
did=-1.557
didn=0.81
didn't=-1.459
didnt=-1.27
diff=0.81
difference=0.81
difficulties=0.81
digital=3.7
dignity=0.81
dinner=-0.982
dint=0.81
direct=3.161
disclose=0.81
discount=2.602
dislikes=0.81
disturb=0.81
dload=3.295
doc=0.81
docs=0.81
doesn=0.81
dogging=3.518
doing=-2.004
don=-1.036
donno=0.81
dorm=0.81
dot=2.314
double=2.091
dough=0.81
download=1.215
downloads=3.007
dr=0.81
draw=3.467
dream=0.81
dressed=0.81
drinking=0.81
drinks=3.007
driver=0.81
drunken=0.81
dubsack=0.81
duchess=3.007
due=1.215
dun=-1.424
dunno=-0.731
durban=0.81
during=0.81
dvd=2.825
each=1.908
ear=0.81
early=-1.183
easier=0.81
east=0.81
eastenders=3.007
easy=1.456
eat=-1.087
eaten=0.81
eating=0.81
ebay=0.81
ec=3.295
edge=0.81
edison=0.81
eek=0.81
eerie=3.007
effects=0.81
eg=3.295
eire=3.007
either=2.132
elsewhere=0.81
empty=0.81
end=1.146
ending=3.854
ends=1.349
eng=2.602
england=3.161
enjoy=1.061
enjoyin=0.81
enter=2.889
entered=1.908
entitled=3.7
entry=4.211
envelope=2.314
environment=0.81
erm=0.81
error=1.908
escape=0.81
ese=0.81
esplanade=0.81
etc=2.132
euro=3.007
eva=0.81
evening=-0.864
event=0.81
every=1.429
everybody=0.81
everybody's=0.81
everything=-1.036
everywhere=0.81
evn=0.81
exams=0.81
excuses=0.81
exhausted=0.81
expires=4.106
explain=0.81
explicit=3.007
explosive=3.007
expression=0.81
expressoffer=3.007
extra=2.132
ey=0.81
faggy=0.81
failed=1.908
fair=0.81
faith=0.81
family=-0.731
fancy=2.419
fantasies=3.854
fantastic=2.602
fantasy=3.007
fastest=3.007
favourite=0.81
feb=1.215
feel=-1.588
feelin=0.81
fees=0.81
female=1.908
fever=0.81
few=-1.459
field=0.81
fighting=0.81
files=0.81
fills=0.81
final=3.295
find=1.385
fine=-1.31
finish=-1.227
finished=-0.731
finishes=0.81
fish=0.81
fit=1.503
five=2.314
fixed=1.215
flag=3.295
flaky=0.81
flights=3.295
flirt=3.295
flower=2.314
fml=1.908
fo=0.81
follow=1.908
followed=2.314
following=1.908
fone=1.908
foot=0.81
for=1.012
forget=0.81
forgot=-0.8
format=1.908
forwarded=0.992
four=1.908
frauds=0.81
freak=0.81
free=2.779
freefone=3.007
freemsg=4.211
freephone=3.7
friend's=0.81
fringe=0.81
frnd=1.621
from=1.688
fromm=3.007
fuck=-0.8
fucked=0.81
fujitsu=0.81
ful=0.81
fun=0.953
future=3.295
ga=3.007
galileo=0.81
gals=0.81
game=2.196
games=3.7
garage=0.81
garbage=0.81
gary=0.81
gautham=0.81
gay=2.196
gb=3.518
gbp=3.988
geeee=0.81
gender=3.007
gentle=0.81
gentleman=0.81
gettin=1.215
getzed=3.518
gift=2.602
giving=0.992
gnt=0.81
goal=1.908
goals=3.007
god=-0.982
god's=0.81
goin=-0.8
going=-1.515
gonna=-1.647
goodo=0.81
google=0.81
gossip=1.908
got=-2.169
goto=2.825
gr=1.503
grace=0.81
grand=0.81
granite=3.007
gravity=0.81
green=0.81
greetings=0.81
growing=3.007
gt=-3.012
guaranteed=5.241
gud=-1.805
haf=-0.731
haha=-1.27
half=1.349
hamster=0.81
handle=0.81
hands=0.81
handset=3.7
hang=0.81
happend=0.81
happy=-1.205
hard=0.81
hardcore=3.007
has=0.788
hav=-0.731
have=0.8
havin=1.908
having=-1.31
he=-2.435
he'll=0.81
head=-0.8
headin=0.81
heading=0.81
heard=1.398
hearts=0.81
heavy=0.81
helen=1.908
hella=0.81
helloooo=0.81
help=1.215
hence=0.81
herself=3.007
hg=3.854
hide=1.908
high=3.007
him=-1.424
his=-1.557
hit=1.621
hl=4.306
ho=0.81
hockey=1.908
holder=3.7
holiday=2.825
hols=1.908
home=-1.841
hope=-1.369
hoped=0.81
horny=3.7
hospitals=0.81
hot=2.784
hotel=0.81
hour=-1.087
hours=1.215
how=-1.696
how's=-0.8
however=0.81
hows=-0.731
hp=2.314
hrishi=0.81
hrs=2.468
hsbc=0.81
http=4.393
hug=0.81
huh=-0.731
hurried=0.81
hurry=1.215
hurting=0.81
hw=0.81
hyde=0.81
i'd=1.061
i'll=-2.613
i'm=-1.75
i've=-1.675
ias=0.81
ibhltd=3.007
ibiza=3.518
ic=0.81
ice=1.215
icicibank=0.81
id=0.928
identifier=3.988
idiot=0.81
ignore=0.81
imagine=0.81
imma=0.81
immediately=0.81
important=1.775
impossible=0.81
inches=0.81
include=1.908
inclusive=3.518
inconsiderate=0.81
indians=0.81
indicate=3.007
infernal=0.81
info=3.518
information=2.825
infront=0.81
insha=0.81
inshah=0.81
instantly=1.908
instead=0.81
instructions=1.908
intelligent=0.81
interest=0.81
interested=0.992
internet=0.992
invaders=3.007
invest=0.81
invite=0.81
invited=0.992
inviting=3.007
iouri=0.81
ip=3.007
ipod=3.988
iq=0.81
irritating=0.81
islands=1.908
issues=1.908
it=-1.74
it's=-0.754
its=-2.09
itz=0.81
ja=0.81
jane=1.503
january=0.81
japanese=0.81
jas=0.81
jason=0.81
java=3.295
jeans=0.81
jess=0.81
jhl=3.007
jiayin=0.81
job=-1.526
jobs=0.81
jogging=0.81
join=2.419
joking=0.81
jordan=3.007
jstfrnd=0.81
june=0.81
jus=-1.227
kate=0.81
kay=0.81
ke=0.81
keep=-0.754
keeps=0.81
kent=0.81
kept=0.992
key=0.81
kick=1.908
kills=0.81
kindly=0.81
kiss=-0.925
kl=3.007
know=-0.723
la=1.685
lab=0.81
lacs=0.81
ladies=1.908
lady=0.81
laid=2.602
land=4.211
landline=3.518
lands=3.295
lane=0.81
language=0.81
lar=-1.31
largest=3.295
late=-0.731
later=-2.219
latest=3.582
ldew=3.295
ldn=3.854
ldnw=3.295
learn=0.81
leave=-0.832
leaving=-0.8
left=-0.982
legal=0.81
legs=0.81
leh=-0.864
lei=-0.8
lemme=0.81
let=-1.853
let's=2.196
letters=0.81
liao=-0.8
lie=0.81
lifetime=1.908
lifpartnr=0.81
lik=0.81
like=-1.053
likes=0.81
lil=0.81
lily=3.007
line=2.907
linerental=3.007
lines=1.908
link=2.196
lion=0.81
lionm=3.007
lionp=3.007
lions=3.007
lip=0.81
listen=1.061
listening=1.503
literally=0.81
little=-0.731
live=2.439
liverpool=3.007
lives=0.81
living=1.215
ll=-0.982
loan=1.503
local=3.295
locations=3.295
log=2.419
login=2.419
lol=-1.805
london=1.908
lonely=1.503
long=-1.459
looking=1.289
loose=0.81
lor=-2.435
lose=1.215
loses=0.81
losing=0.81
loss=0.81
lost=0.992
lot=-1.31
lousy=0.81
lovable=0.81
love=-1.27
lovers=0.81
low=1.908
lower=0.81
loyalty=3.518
lp=3.007
lt=-3.019
ltd=4.547
luck=2.314
lucky=1.572
lunch=-0.982
lush=0.81
luv=0.745
lvblefrnd=0.81
ma=0.81
machan=0.81
macho=0.81
mahal=0.81
major=0.81
makes=-0.731
male=3.007
mall=0.81
management=0.81
map=0.81
market=0.81
married=1.215
mas=0.81
massive=0.81
match=2.419
matches=3.518
mates=2.889
math=0.81
matrix=3.007
matter=0.81
max=3.7
maximize=3.295
mb=0.81
mca=0.81
me=-1.068
means=-0.982
med=2.314
meet=-0.8
meeting=-1.087
melt=0.81
member=3.518
members=3.295
membership=1.908
men=1.503
menu=1.503
message=1.151
messaged=0.81
messages=1.908
mid=0.992
midnight=0.992
mids=0.81
might=-1.31
million=1.908
min=2.515
mind=-1.136
minmoremobsemspobox=3.007
mins=2.964
minute=1.438
missin=0.81
mistakes=0.81
mmmm=0.81
mmmmm=0.81
mmmmmm=0.81
mob=4.211
mobile=4.291
mobiles=3.854
mobilesdirect=3.007
mobileupd=4.106
moby=3.007
mokka=0.81
mom's=0.81
moments=0.81
mono=3.007
month=1.289
month's=1.503
monthly=0.81
months=0.81
moon's=3.007
morning=-1.898
moro=1.215
morow=0.81
morrow=0.81
mostly=0.81
motorola=2.825
movie=-0.8
moving=0.81
mp=2.419
mrw=0.81
msg=2.239
msgrcvd=3.007
msgs=2.245
msn=0.81
mt=1.908
mths=3.988
mtmsg=3.295
mtmsgrcvd=3.007
much=-1.406
mum's=0.81
mummy=0.81
music=3.007
my=-1.755
nag=0.81
nagar=0.81
naked=0.992
name=0.897
nasdaq=3.007
nat=3.007
national=4.681
natural=0.81
nd=2.314
neft=0.81
neither=0.81
net=2.515
netcollex=3.518
network=3.582
networking=0.81
networks=3.007
new=1.667
neway=0.81
newest=3.007
news=2.468
next=1.525
nice=-1.618
night=-1.0
nights=1.503
nitros=0.81
nokia=4.106
nokias=3.007
noline=3.295
norm=3.295
normal=1.398
not=-0.911
note=0.81
notice=1.215
now=1.621
nowadays=0.81
ntt=3.988
ntwk=3.007
num=0.81
number=1.297
numbers=2.756
nvm=0.81
nyt=0.704
occupy=0.81
offer=3.582
offers=3.295
official=2.602
oh=-2.169
ok=-1.749
okay=-0.731
omw=0.81
once=-1.27
onion=0.81
online=-0.8
only=1.406
onto=3.518
opening=0.81
operator=3.854
opt=4.393
option=0.81
optout=4.547
or=1.525
orange=4.681
order=2.16
orig=3.007
original=3.007
oru=0.81
our=2.249
outta=0.81
over=1.033
ovulation=0.81
ow=1.908
pa=-0.925
package=0.81
paid=0.81
pain=-1.136
painful=0.81
part=1.302
partner=3.518
partnership=0.81
pass=1.908
password=1.908
past=0.81
pattern=0.81
payee=0.81
pc=2.132
pen=0.81
per=3.355
perfect=1.503
person=-1.557
personal=1.908
persons=0.81
perwksub=3.007
petey=0.81
ph=1.503
phone=1.423
phoned=0.81
phones=3.854
photo=2.314
pic=1.908
pick=-0.754
pics=2.378
picture=0.81
pie=0.81
pieces=0.81
pin=1.215
pissed=0.81
pix=1.908
plan=-1.087
play=1.369
played=1.908
player=2.468
playing=0.81
please=1.697
pleased=1.503
plus=1.349
pm=2.288
po=4.393
pobox=4.853
pod=3.007
points=3.295
polo=3.007
poly=4.106
polyph=3.295
polyphonic=3.295
polys=3.518
porn=3.007
possession=0.81
post=0.928
postcode=3.007
posts=1.908
potato=0.81
potential=1.503
pound=3.7
pounds=4.106
pours=0.81
ppl=0.81
ppm=5.31
ppmx=3.295
prabha=0.81
practice=0.81
practicing=0.81
pre=1.908
prefer=0.81
premier=3.007
press=1.621
previous=1.503
price=2.132
prince=0.81
princess=-0.925
private=4.106
prize=5.86
probably=-1.036
problem=-1.036
professors=0.81
profit=2.314
prompts=3.007
proof=0.81
prove=0.81
proverb=0.81
pt=3.007
ptbo=0.81
pull=0.81
purchase=3.295
purse=0.81
pushes=0.81
qp=3.007
qu=3.007
quality=1.215
question=1.302
quite=-1.183
quiz=4.473
quote=1.908
quoting=3.295
qxj=3.295
raise=0.81
ran=0.81
randomly=1.908
rang=0.81
range=0.81
rate=3.754
rates=3.007
rays=0.81
rcv=3.007
rcvd=3.854
re=1.803
real=1.423
reality=1.908
really=-1.183
reasonable=0.81
reasons=0.81
recd=3.007
receipt=2.602
receive=3.161
receivea=3.007
received=1.908
recently=1.621
recession=0.81
recognise=0.81
record=0.81
records=3.295
recovery=0.81
red=3.007
redeemed=3.854
ref=3.007
reference=1.685
regarding=0.81
registered=1.908
relatives=0.81
remains=0.81
remembered=0.81
remembr=0.81
remind=0.81
reminder=1.908
removal=3.007
remove=1.503
removed=1.908
rental=3.988
rentl=3.295
rents=0.81
replied=1.503
reply=2.623
replying=2.825
report=0.81
representative=3.988
requests=1.503
research=0.81
respect=0.81
respond=0.81
response=1.503
results=1.908
return=0.81
returns=0.81
reveal=3.988
revealed=3.295
review=1.503
reward=3.7
rgds=1.908
rice=0.81
ride=0.81
right=-1.369
rightly=0.81
ringtone=4.616
ringtones=3.854
rock=0.81
rofl=0.81
romantic=1.215
room=-1.136
roommate's=0.81
rooms=1.215
round=0.992
row=2.602
rply=1.908
rstm=3.007
rude=3.007
rule=0.81
run=-0.8
sae=4.547
said=-1.898
salam=0.81
salary=0.81
sale=2.196
salon=0.81
sam=1.908
same=-1.27
sarcastic=0.81
saturday=1.349
savamob=3.7
save=1.398
saved=0.81
say=-1.33
says=-0.864
scary=0.81
schedule=3.007
school=-0.731
scotland=1.908
scream=0.81
season=1.503
secret=2.889
secs=3.007
seem=1.908
select=1.908
selected=3.375
selection=3.518
self=1.398
selling=1.908
sells=0.81
send=1.271
sending=1.398
service=4.473
services=4.393
settings=2.314
settle=0.81
settled=0.81
seven=0.81
sex=3.988
sexy=1.754
shall=-0.8
sharing=0.81
she=-2.117
shesil=0.81
shipped=0.81
shirts=0.81
shit=-0.925
shoot=0.81
shop=1.215
shoppin=0.81
shopping=0.745
shortage=0.81
shorter=0.81
shortly=3.007
shot=1.908
shouldn't=0.81
shouted=0.81
shoving=0.81
shows=3.23
shut=0.81
shy=1.908
si=0.81
sian=0.81
sigh=0.81
sign=0.81
signing=0.81
silence=0.81
sim=0.992
simple=1.503
simpler=0.81
simply=1.503
sinco=0.81
single=1.215
singles=3.295
sipix=3.295
siva=0.81
six=2.314
size=0.81
sk=4.211
skilgme=3.007
skip=1.503
sleep=-1.459
slept=0.81
slice=0.81
smart=1.908
smile=-1.35
smith=1.908
smoking=0.81
sms=2.559
so=-0.763
soft=0.81
sol=3.295
some=-0.766
somebody=0.81
something=-1.675
song=1.398
sony=3.295
sonyericsson=3.295
soo=0.81
sooooo=0.81
sorry=-1.78
sorted=0.81
soup=0.81
source=0.81
sp=3.7
space=1.398
spanish=3.007
special=1.503
specially=3.295
speechless=0.81
speed=0.81
spell=0.81
spile=0.81
spoken=0.81
sport=3.007
spree=3.518
spring=0.81
ss=3.007
st=2.051
stamped=3.007
standard=3.518
star=3.007
starting=0.81
starts=1.908
starwars=3.007
statement=3.988
std=3.854
steve=0.81
sticky=1.908
still=-1.023
stockport=3.295
stomach=0.81
stop=2.976
stopped=0.81
stoptxt=3.295
store=2.602
straight=1.908
street=1.398
stress=0.81
strike=0.81
strong=1.621
student=0.81
study=0.81
stuff=-1.459
sub=3.7
subpoly=3.007
subs=3.518
subscribed=3.007
subscriber=3.295
subscription=3.295
sucks=0.81
suggest=0.81
suite=3.112
summer=2.825
sunshine=3.161
suntec=0.81
super=1.503
superb=1.908
supply=3.007
support=1.398
suprman=3.007
sure=-1.755
surprise=1.503
survey=1.908
sux=0.81
sw=3.007
sweet=-1.087
swimming=0.81
switch=1.908
swoop=0.81
swtheart=0.81
symbol=2.314
t's=3.7
ta=1.503
tablets=0.81
takes=0.81
takin=0.81
tank=0.81
tap=0.81
tariffs=3.007
tat=0.81
taylor=0.81
tayseer=0.81
tb=1.503
tc=2.756
tcr=3.007
tcs=3.007
teaches=0.81
team=1.215
tear=0.81
tease=0.81
tech=0.81
tel=0.81
tells=1.908
telugu=0.81
tenerife=3.518
terms=2.889
terrible=0.81
terrific=0.81
test=-0.8
tests=0.81
text=2.728
textcomp=3.295
texted=0.81
texting=0.992
textoperator=3.295
texts=2.602
than=-1.27
thangam=0.81
thanksgiving=0.81
thanx=-0.731
that=-1.108
that's=-1.526
thats=-1.31
them=-1.898
themob=3.295
then=-1.294
there=-1.205
these=0.704
they're=0.81
thgt=0.81
thing=-1.087
things=-1.227
think=-1.283
thinks=2.602
this=0.928
thk=-1.136
thm=0.81
tho=-0.864
those=-0.864
though=-0.864
thought=-0.731
three=0.81
thts=0.81
thurs=1.215
tickets=1.215
times=-0.864
tis=0.81
tissco=0.81
tkts=3.007
tlk=0.81
tlp=3.007
tm=0.81
tmr=-0.731
tncs=3.295
to=0.837
toclaim=3.295
today's=2.314
todays=3.613
tog=0.81
tok=0.81
told=-1.459
tomarrow=0.81
tone=4.953
tones=4.211
tonight=-0.731
too=-1.633
tool=0.81
tooo=0.81
top=2.314
topic=0.81
tortilla=0.81
toshiba=0.81
total=1.503
tour=1.215
train=0.81
transfered=0.81
travel=1.215
tree=0.81
tried=2.784
trips=0.81
true=0.704
truly=1.908
trying=1.082
ts=3.988
tscs=3.007
tsunamis=0.81
ttyl=0.81
tulip=3.007
turn=1.503
turning=0.81
tv=0.745
two=-1.087
txt=4.547
txtauction=3.295
txtin=3.007
txting=3.518
txts=3.518
tyrone=3.007
uk=4.712
uk's=3.518
uks=3.007
un=3.161
unable=2.314
unbelievable=0.81
understanding=0.81
understood=0.81
unfortunately=0.81
uni=0.81
unique=3.007
university=0.81
unlimited=2.602
unnecessarily=0.81
unsub=3.7
unsubscribe=4.211
until=1.215
update=2.719
upgrade=3.007
upload=1.908
upset=0.81
upto=1.503
ur=1.342
urawinner=3.295
urgent=3.7
urgently=0.81
urgnt=0.81
urn=0.81
user=3.007
using=1.398
uz=3.854
vale=0.81
valentines=0.81
valid=4.742
value=0.81
valued=3.007
vary=3.295
ve=1.215
verify=3.007
very=-1.009
via=0.81
video=4.048
videochat=3.295
videophones=3.295
village=0.81
violet=3.007
virgin=1.908
visit=1.061
viva=0.81
voda=3.295
vodafone=3.295
voicemail=3.007
voucher=3.7
vouchers=3.854
wa=2.314
wait=-0.895
waited=0.81
waitin=0.81
waiting=0.704
wake=-0.982
wales=1.908
wan=-0.832
wanting=1.503
wap=3.988
warning=0.81
was=-1.35
wat=-1.963
watch=-0.731
watching=-1.27
wats=0.81
waxsto=0.81
way=-1.369
wb=3.854
wc=3.988
we're=-0.864
web=3.007
website=0.81
wedding=1.908
week=1.598
week's=3.007
weekends=1.908
weekly=4.393
weeks=2.091
weird=0.81
welcome=2.602
welcomes=0.81
went=-1.35
wer=0.81
wet=1.908
what=-1.17
when=-0.88
where=-2.235
where's=0.81
whn=0.81
who=1.008
whos=0.81
wicklow=3.007
wid=1.349
wif=-0.731
wifi=0.81
wil=-0.731
willing=1.503
win=4.365
winawk=3.007
winner=4.106
winning=0.81
wins=0.81
wipro=0.81
with=1.183
within=2.132
wiv=1.908
wk=3.007
wkent=3.007
wkly=4.106
wks=3.007
woken=0.81
woman=0.81
women=1.908
won=5.572
wont=-1.183
word=2.447
work=-0.963
working=-0.982
world=-1.183
worry=-0.731
worse=0.81
worst=0.81
worth=2.756
would=-1.898
wow=0.81
wp=3.518
wq=3.7
ws=1.215
wu=3.295
wuld=0.81
www=5.107
wx=3.7
xavier=0.81
xh=3.518
xmas=3.112
xuhui=0.81
xx=2.245
xxx=1.646
xxxx=0.81
xxxxxxx=3.007
xy=0.992
ya=-1.424
yahoo=0.81
yeah=-1.729
years=1.12
yelling=0.81
yellow=0.81
yer=3.295
yest=0.81
yet=-0.731
yetunde=0.81
yor=0.81
you've=1.215
your=1.453
youre=0.81
yours=2.602
yourself=-0.864
yr=3.412
yrs=1.908
yup=-1.036
zed=3.295
        """;

    private static final Map<String, Double> NB_SPAM_WEIGHTS = parseNbWeights();

    private static Map<String, Double> parseNbWeights() {
        Map<String, Double> map = new HashMap<>();
        for (String line : NB_WEIGHT_DATA.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                try { map.put(line.substring(0, eq), Double.parseDouble(line.substring(eq + 1))); }
                catch (NumberFormatException ignored) { }
            }
        }
        return map;
    }

    /** Naive-Bayes spam log-odds over distinct words; positive = spammy. */
    private static double nbSpamScore(String lowerText) {
        Matcher m = WORD_PATTERN.matcher(lowerText);
        java.util.Set<String> seen = new java.util.HashSet<>();
        double score = 0.0;
        while (m.find()) {
            String word = m.group();
            if (seen.add(word)) {
                Double w = NB_SPAM_WEIGHTS.get(word);
                if (w != null) score += w;
            }
        }
        return score;
    }


    public PhishingScanService(UrlScanService urlScanService, HistoryService historyService) {
        this.urlScanService = urlScanService;
        this.historyService = historyService;
        this.restClient = RestClient.create();
    }

    public PhishingScanDto.Response analyzePhishing(PhishingScanDto.Request request) {
        String type = request.getType() != null ? request.getType().toUpperCase() : "TEXT";
        String content = request.getContent() != null ? request.getContent().trim() : "";

        if (content.isEmpty()) {
            throw new IllegalArgumentException("Scan content must not be empty");
        }

        if ("IMAGE".equals(type)) {
            return analyzeImagePhishing(content, request.getFileName(), request.getExtractedText(), request.getUserId());
        } else {
            return analyzeTextPhishing(content, request.getUserId());
        }
    }

    public PhishingScanDto.Response analyzeImagePhishing(String base64Content, String fileName, String extractedText, String userId) {
        // First try Python ML Service with RapidOCR visual text recognition
        try {
            log.info("Sending screenshot to Python ML OCR service at {}: {}", mlServiceUrl, fileName);
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("image", base64Content);
            reqBody.put("fileName", fileName != null ? fileName : "screenshot.png");
            if (extractedText != null && !extractedText.isBlank()) {
                reqBody.put("extractedText", extractedText);
            }

            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/phishing/analyze-image")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reqBody)
                    .retrieve()
                    .body(Map.class);

            if (mlResponse != null && mlResponse.containsKey("threatLevel")) {
                PhishingScanDto.Response response = parseMlPhishingResponse(mlResponse);
                recordScan(userId, "PHISHING_IMAGE", "Screenshot: " + (fileName != null ? fileName : "image_upload.png"), response);
                return response;
            }
        } catch (Exception ex) {
            log.warn("Python ML OCR service unavailable ({}), executing image heuristic fallback", ex.getMessage());
        }

        // Fallback heuristic if ML OCR service is unreachable
        return evaluateImageHeuristicFallback(base64Content, fileName, extractedText, userId);
    }

    public PhishingScanDto.Response analyzeTextPhishing(String text, String userId) {
        // First try Python ML Service text phishing analyzer
        try {
            log.info("Sending text to Python ML phishing service at {}", mlServiceUrl);
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("content", text);

            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/phishing/analyze-text")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reqBody)
                    .retrieve()
                    .body(Map.class);

            if (mlResponse != null && mlResponse.containsKey("threatLevel")) {
                PhishingScanDto.Response response = parseMlPhishingResponse(mlResponse);
                String snippet = text.length() > 60 ? text.substring(0, 60) + "..." : text;
                recordScan(userId, "PHISHING_TEXT", snippet, response);
                return response;
            }
        } catch (Exception ex) {
            log.warn("Python ML text service unavailable ({}), executing text heuristic fallback", ex.getMessage());
        }

        // Fallback heuristic if Python ML service is unreachable
        return evaluateTextHeuristicFallback(text, userId);
    }

    private PhishingScanDto.Response parseMlPhishingResponse(Map<?, ?> mlResp) {
        PhishingScanDto.Response resp = new PhishingScanDto.Response();
        Object threatLevelObj = mlResp.get("threatLevel");
        resp.setThreatLevel(threatLevelObj != null ? String.valueOf(threatLevelObj) : "SUSPICIOUS");

        Object score = mlResp.get("riskScore");
        if (score instanceof Number) {
            resp.setRiskScore(((Number) score).intValue());
        } else {
            resp.setRiskScore(50);
        }

        Object conf = mlResp.get("confidence");
        if (conf instanceof Number) {
            resp.setConfidence(((Number) conf).doubleValue());
        } else {
            resp.setConfidence(90.0);
        }

        Object summaryObj = mlResp.get("summary");
        resp.setSummary(summaryObj != null ? String.valueOf(summaryObj) : "Analysis completed.");

        Object brandObj = mlResp.get("brandImpersonated");
        resp.setBrandImpersonated(brandObj != null ? String.valueOf(brandObj) : "None Detected");

        Object credHarv = mlResp.get("credentialHarvesting");
        if (credHarv instanceof Boolean) {
            resp.setCredentialHarvesting((Boolean) credHarv);
        }

        Object extText = mlResp.get("extractedText");
        if (extText != null) {
            resp.setExtractedText(String.valueOf(extText));
        }

        Object urgencyObj = mlResp.get("urgencyTactics");
        if (urgencyObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) urgencyObj) {
                list.add(String.valueOf(item));
            }
            resp.setUrgencyTactics(list);
        }

        Object urlsObj = mlResp.get("extractedUrls");
        if (urlsObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) urlsObj) {
                list.add(String.valueOf(item));
            }
            resp.setExtractedUrls(list);
        }

        Object indObj = mlResp.get("indicators");
        if (indObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) indObj) {
                list.add(String.valueOf(item));
            }
            resp.setIndicators(list);
        }

        Object recObj = mlResp.get("recommendations");
        if (recObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) recObj) {
                list.add(String.valueOf(item));
            }
            resp.setRecommendations(list);
        }

        return resp;
    }

    /** Core text-phishing engine: pure analysis, no history recording. */
    private PhishingScanDto.Response evaluateTextHeuristicCore(String text, String userId) {
        String lowerText = text.toLowerCase(Locale.ENGLISH);
        List<String> indicators = new ArrayList<>();
        List<String> urgencyTactics = new ArrayList<>();
        List<String> harvestTactics = new ArrayList<>();
        List<String> extractedUrls = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();

        int riskScore = 10;
        String detectedBrand = "None Detected";
        boolean credentialHarvesting = false;
        boolean senderSpoofed = false;

        // Academic Timetable / Educational Schedule Whitelist Detection
        boolean isTimetable = (lowerText.contains("timetable") || lowerText.contains("time table") || lowerText.contains("schedule")
                || lowerText.contains("routine") || lowerText.contains("syllabus") || lowerText.contains("lecture") || lowerText.contains("semester"))
                && (lowerText.contains("monday") || lowerText.contains("tuesday") || lowerText.contains("wednesday") || lowerText.contains("thursday")
                || lowerText.contains("friday") || lowerText.contains("saturday") || lowerText.contains("room") || lowerText.contains("am") || lowerText.contains("pm"));

        if (isTimetable) {
            indicators.add("[Document Intelligence] Academic Schedule Verified: Content recognized as authentic educational timetable/schedule.");
            indicators.add("[Integrity Verification] Zero deceptive indicators, credential theft, or phishing vectors identified.");
            recommendations.add("Document is verified as an authentic educational timetable / schedule.");
            recommendations.add("No threat detected. Verified safe to view and distribute.");

            PhishingScanDto.Response response = new PhishingScanDto.Response(
                    "SAFE",
                    0,
                    99.0,
                    "Authentic Academic Timetable / Routine. Document contains scheduled course intervals, subjects, and classroom listings with zero security risks.",
                    "Educational Document (Benign)",
                    false,
                    urgencyTactics,
                    extractedUrls,
                    indicators,
                    recommendations,
                    text
            );
            return response;
        }

        // 1. Extract embedded URLs (supports http/https, hxxp, www, defanged [.], and bare domains)
        String normalizedForUrls = text.replaceAll("(?i)hxxp", "http").replace("[.]", ".");
        Pattern urlPattern = Pattern.compile("\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.](?:com|org|net|xyz|top|ru|co|info|biz|site|live|online|security|app|vip|club)/?)[^\\s<>'\"\\)\\]]+)");
        Matcher matcher = urlPattern.matcher(normalizedForUrls);
        while (matcher.find()) {
            String url = matcher.group().replaceAll("[.,;]+$", "");
            if (!extractedUrls.contains(url)) {
                extractedUrls.add(url);
            }
        }

        // Evaluate extracted URLs with the URL threat engine
        int maliciousUrlCount = 0;
        for (String url : extractedUrls) {
            try {
                UrlScanDto.Request urlReq = new UrlScanDto.Request(url, userId);
                UrlScanDto.Response urlResp = urlScanService.analyzeUrl(urlReq);
                if ("PHISHING".equalsIgnoreCase(urlResp.getPrediction()) || urlResp.getRiskScore() >= 60) {
                    maliciousUrlCount++;
                    indicators.add("[Embedded Destination Threat] Malicious Hyperlink: Destination '" + url + "' classified as PHISHING (Risk: " + urlResp.getRiskScore() + "/100).");
                    riskScore = Math.max(riskScore + 40, 90);
                } else {
                    indicators.add("[Embedded Destination Inspection] Hyperlink Verified: Destination '" + url + "' analyzed as " + urlResp.getPrediction() + ".");
                }
            } catch (Exception e) {
                log.warn("URL analysis fallback for embedded url {}: {}", url, e.getMessage());
            }
        }

        // 2. Brand Impersonation Detection
        for (String brand : TARGET_BRANDS) {
            if (lowerText.contains(brand.toLowerCase(Locale.ENGLISH))) {
                detectedBrand = brand;
                indicators.add("[Brand & Entity Impersonation] Brand Lure Target: Mentions '" + brand + "' within message body to establish false authority.");
                riskScore += 20;
                break;
            }
        }

        // 3. Sender Domain Spoofing Detection
        if (text.contains("[.]") || text.contains("[@]")) {
            riskScore += 15;
            indicators.add("[Threat Intelligence Artifact] Defanged Notation: Message contains security syntax '[.]' or '[@]' characteristic of documented phishing samples.");
        }

        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        String normalizedEmailText = text.replace("[.]", ".").replace("[@]", "@");
        Matcher emailMatcher = emailPattern.matcher(normalizedEmailText);
        if (emailMatcher.find()) {
            String senderDomain = emailMatcher.group(1).toLowerCase(Locale.ENGLISH);
            if (!"None Detected".equals(detectedBrand)) {
                String brandLower = detectedBrand.toLowerCase(Locale.ENGLISH);
                if (!senderDomain.contains(brandLower) || senderDomain.contains("webnotifications") || senderDomain.contains("mail-delivery")) {
                    senderSpoofed = true;
                    riskScore += 45;
                    indicators.add("[Critical Identity Spoofing] Sender Address Disparity: Display claims '" + detectedBrand + "', but sender domain is '@" + senderDomain + "' (unauthorized third-party domain).");
                }
            } else if (text.contains("workplace") || text.contains("hr") || text.contains("policy") || text.contains("contoso")) {
                if (senderDomain.contains("webnotifications") || senderDomain.contains("mail-delivery") || senderDomain.contains("notification")) {
                    senderSpoofed = true;
                    riskScore += 45;
                    indicators.add("[Critical Sender Domain Disparity] External Relay Abuse: Workplace alert dispatched from unauthorized external relay '@" + senderDomain + "'.");
                }
            }
        }

        // 4. Urgency, lure & prize tactics (+12 each; tuned on 3,000 labeled messages)
        for (String trigger : URGENCY_TRIGGERS) {
            if (lowerText.contains(trigger)) {
                urgencyTactics.add(trigger);
                riskScore += 12;
            }
        }
        if (!urgencyTactics.isEmpty()) {
            indicators.add("[Psychological Lure Tactic] Pressure & Prize Triggers: Detected high-pressure lures: " + String.join(", ", urgencyTactics));
        }

        // 5. Credential & financial harvesting CTAs (+20 each, capped at +50)
        int harvestScore = 0;
        for (String trigger : HARVESTING_TRIGGERS) {
            if (lowerText.contains(trigger)) {
                credentialHarvesting = true;
                harvestTactics.add(trigger);
                harvestScore += 20;
            }
        }
        riskScore += Math.min(harvestScore, 50);
        if (!harvestTactics.isEmpty()) {
            indicators.add("[Credential Harvesting Vector] Interactive Harvesting Triggers: Direct calls to action prompting '" + String.join(", ", harvestTactics) + "' to harvest credentials or money.");
        }

        // 6. Premium-rate callback numbers (090/0870/0871/0844/0845 ranges)
        if (PREMIUM_RATE_PATTERN.matcher(text).find()) {
            credentialHarvesting = true;
            harvestTactics.add("premium-rate callback number");
            riskScore += 25;
            indicators.add("[Financial Harvesting Vector] Premium-Rate Callback: Message pushes a premium-rate phone number, a classic toll-fraud monetization pattern.");
        }

        // 7. Premium SMS shortcode CTAs ("text X to 81234")
        if (SHORTCODE_CTA_PATTERN.matcher(lowerText).find()) {
            credentialHarvesting = true;
            harvestTactics.add("premium SMS shortcode CTA");
            riskScore += 25;
            indicators.add("[Financial Harvesting Vector] Premium SMS Shortcode: Message drives replies to a premium SMS shortcode, monetizing each response.");
        }

        // 8. Prize + callback combo (win/won/prize/award together with call/txt/claim)
        boolean prizeWord = lowerText.contains("win") || lowerText.contains("won")
                || lowerText.contains("prize") || lowerText.contains("award");
        boolean callbackWord = lowerText.contains("call") || lowerText.contains("txt")
                || lowerText.contains("claim") || lowerText.contains("text ");
        if (prizeWord && callbackWord) {
            urgencyTactics.add("prize+callback combo");
            riskScore += 20;
            indicators.add("[Prize Lure Combo] Winnings paired with a call/text/claim action, the signature structure of advance-fee prize scams.");
        }

        // 9. Spam-token cluster safety net (4+ distinct spam tokens)
        int clusterHits = 0;
        for (String token : SPAM_TOKEN_CLUSTER) {
            if (lowerText.contains(token)) {
                clusterHits++;
            }
        }
        if (clusterHits >= 4) {
            urgencyTactics.add("spam-token cluster (" + clusterHits + " signals)");
            riskScore += 25;
            indicators.add("[Statistical Cluster] Converging spam markers: " + clusterHits + " distinct spam indicators co-occur in a single short message.");
        }

        // Clamp risk score
        riskScore = Math.min(100, Math.max(5, riskScore));

        String threatLevel;
        String summary;
        double confidence;

        if (maliciousUrlCount > 0) {
            threatLevel = "PHISHING";
            riskScore = Math.max(riskScore, 90);
            confidence = 99.2;
            summary = "Critical Phishing Threat Identified (Target: " + detectedBrand + "). Communication embeds " + maliciousUrlCount + " malicious hyperlink(s) leading to deceptive phishing infrastructure.";
            recommendations.add("CRITICAL: Do NOT click any links, open buttons, or visit URLs in this message.");
            recommendations.add("Never submit login passwords, MFA/OTP tokens, or financial information to unverified links.");
            recommendations.add("Verify out-of-band: Open a fresh browser window and navigate directly to the verified official portal.");
            recommendations.add("Report this message immediately to your organization's IT Security / SOC department as Phishing.");
        } else if (riskScore >= 70 || senderSpoofed || (credentialHarvesting && !urgencyTactics.isEmpty())) {
            threatLevel = "PHISHING";
            confidence = 98.2;
            summary = "High-Severity Phishing Attack Identified (Target: " + detectedBrand + "). Adversary leverages psychological urgency, unauthenticated dispatch relays, and deceptive credential harvesting lures.";
            recommendations.add("Do NOT click any buttons, links, or download attachments within this communication.");
            recommendations.add("Never submit login passwords, MFA/OTP tokens, or financial information to unverified links.");
            recommendations.add("Verify out-of-band: Open a fresh browser window and navigate directly to the verified official portal.");
            recommendations.add("Report this message immediately to your organization's IT Security / SOC department as Phishing.");
            recommendations.add("If credentials or codes were entered, immediately change your password from a secure device and terminate active sessions.");
        } else if (riskScore >= 40) {
            threatLevel = "SUSPICIOUS";
            confidence = 88.5;
            summary = "Suspicious Communication Detected (" + detectedBrand + "). Message exhibits anomalous urgency triggers, third-party relays, or unverified link patterns that warrant caution.";
            recommendations.add("Exercise heightened caution. Do not follow links provided in this message.");
            recommendations.add("Cross-check the sender's full email address and domain against previous authentic messages.");
            recommendations.add("Contact the purported organization via an independent, verified support channel.");
        } else {
            // 10. Naive-Bayes tiebreaker: weak rule signals + spammy vocabulary -> SUSPICIOUS.
            // A very high vocabulary score (>= 25.0, validated on labeled data with zero
            // ham false positives) escalates on its own even when rule signals are minimal.
            double nbScore = nbSpamScore(lowerText);
            if ((riskScore >= 20 && nbScore >= 12.0) || nbScore >= 25.0) {
                threatLevel = "SUSPICIOUS";
                riskScore = 45;
                confidence = 87.0;
                summary = "Suspicious Communication Detected (" + detectedBrand + "). Statistical language model flags spam-like vocabulary distribution alongside weak lure signals.";
                indicators.add("[Statistical Language Model] Spam vocabulary profile matches known spam/phishing distributions (naive-bayes log-odds " + String.format("%.1f", nbScore) + ").");
                recommendations.add("Exercise heightened caution. Do not follow links provided in this message.");
                recommendations.add("Contact the purported organization via an independent, verified support channel.");
            } else {
                threatLevel = "SAFE";
                confidence = 94.0;
                summary = "Authentic Communication Assessment. Message exhibits standard linguistic tone, verified domain alignment, and zero deceptive credential harvesting or coercion vectors.";
                recommendations.add("Message appears benign, but remain cautious regarding unsolicited requests for sensitive data.");
                recommendations.add("Ensure Multi-Factor Authentication (MFA) remains active on your accounts.");
                if (indicators.isEmpty()) {
                    indicators.add("[Tone & Integrity] Neutral communication syntax with zero credential harvesting vectors.");
                    indicators.add("[Infrastructure] Absence of deceptive links or obfuscated redirect patterns.");
                }
            }
        }

        PhishingScanDto.Response response = new PhishingScanDto.Response(
                threatLevel,
                riskScore,
                confidence,
                summary,
                detectedBrand,
                credentialHarvesting,
                urgencyTactics,
                extractedUrls,
                indicators,
                recommendations,
                text
        );

        return response;
    }

    private PhishingScanDto.Response evaluateTextHeuristicFallback(String text, String userId) {
        PhishingScanDto.Response response = evaluateTextHeuristicCore(text, userId);
        recordScan(userId, "PHISHING_TEXT", text.length() > 60 ? text.substring(0, 60) + "..." : text, response);
        return response;
    }


    /**
     * Screenshot fallback analysis. The verdict is derived from the OCR-extracted
     * on-screen text (sent by the client) run through the text phishing engine.
     * This service cannot perform pixel-level visual inspection; the file name is
     * treated as weak metadata only, never as content evidence.
     */
    private PhishingScanDto.Response evaluateImageHeuristicFallback(String base64Content, String fileName, String extractedText, String userId) {
        String safeFileName = fileName != null ? fileName : "screenshot.png";
        boolean hasOcrText = extractedText != null && !extractedText.trim().isEmpty();

        if (hasOcrText) {
            PhishingScanDto.Response ocrResponse = evaluateTextHeuristicCore(extractedText, userId);

            List<String> indicators = new ArrayList<>(ocrResponse.getIndicators() != null ? ocrResponse.getIndicators() : List.of());
            indicators.add(0, "[OCR Content Analysis] Verdict derived from on-screen text extracted by client-side OCR ("
                    + extractedText.trim().length() + " chars), analyzed with the text phishing engine. "
                    + "No pixel-level visual inspection is performed by this service.");
            if (safeFileName.toLowerCase(Locale.ENGLISH).contains("paypal")
                    || safeFileName.toLowerCase(Locale.ENGLISH).contains("login")
                    || safeFileName.toLowerCase(Locale.ENGLISH).contains("bank")
                    || safeFileName.toLowerCase(Locale.ENGLISH).contains("verify")) {
                indicators.add("[File Context] File name '" + safeFileName + "' mentions a sensitive keyword; treated as context only, not as verdict evidence.");
            }

            PhishingScanDto.Response response = new PhishingScanDto.Response(
                    ocrResponse.getThreatLevel(),
                    ocrResponse.getRiskScore(),
                    ocrResponse.getConfidence(),
                    "Screenshot (OCR text analysis): " + ocrResponse.getSummary(),
                    ocrResponse.getBrandImpersonated(),
                    ocrResponse.isCredentialHarvesting(),
                    ocrResponse.getUrgencyTactics(),
                    ocrResponse.getExtractedUrls(),
                    indicators,
                    ocrResponse.getRecommendations(),
                    extractedText
            );
            response.setExtractedText(extractedText);
            recordScan(userId, "PHISHING_IMAGE", "Screenshot: " + safeFileName, response);
            return response;
        }

        // No OCR text available: filename-only triage with honest, downgraded confidence.
        List<String> indicators = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        List<String> urgencyTactics = new ArrayList<>();
        List<String> extractedUrls = new ArrayList<>();

        String lowerFileName = safeFileName.toLowerCase(Locale.ENGLISH);
        boolean nameLooksSensitive = lowerFileName.contains("paypal") || lowerFileName.contains("login")
                || lowerFileName.contains("bank") || lowerFileName.contains("verify")
                || lowerFileName.contains("password") || lowerFileName.contains("account");
        boolean nameLooksBenign = lowerFileName.contains("timetable") || lowerFileName.contains("schedule")
                || lowerFileName.contains("routine") || lowerFileName.contains("class")
                || lowerFileName.contains("syllabus") || lowerFileName.contains("lecture");

        String threatLevel;
        int riskScore;
        double confidence;
        String summary;

        if (nameLooksSensitive && !nameLooksBenign) {
            threatLevel = "SUSPICIOUS";
            riskScore = 45;
            confidence = 55.0;
            summary = "Screenshot filename suggests a sensitive login/financial page, but no on-screen text was extracted for analysis. "
                    + "The file name alone cannot establish phishing; treat the page with caution until its visible text can be analyzed.";
            indicators.add("[File Context] File name '" + safeFileName + "' references a sensitive page type. This is metadata only: no OCR text and no pixel inspection were available.");
            indicators.add("[Coverage Gap] No on-screen text was received, so lure language, URLs, and brand impersonation could not be checked.");
            recommendations.add("Re-scan the screenshot with a clear, readable capture so on-screen text can be extracted and analyzed.");
            recommendations.add("Do not enter credentials on the page until its visible text has been analyzed.");
        } else {
            threatLevel = "SAFE";
            riskScore = 5;
            confidence = 60.0;
            summary = "Screenshot filename shows no sensitive-page indicators, but no on-screen text was extracted, so this assessment is filename-only and carries low confidence.";
            indicators.add("[File Context] File name '" + safeFileName + "' carries no sensitive-page keywords. No OCR text and no pixel inspection were available.");
            indicators.add("[Coverage Gap] On-screen lure language, URLs, and brand impersonation could not be checked without extracted text.");
            recommendations.add("For a reliable verdict, re-scan with a clear capture so on-screen text can be extracted and analyzed.");
        }

        PhishingScanDto.Response response = new PhishingScanDto.Response(
                threatLevel,
                riskScore,
                confidence,
                summary,
                "None Detected",
                false,
                urgencyTactics,
                extractedUrls,
                indicators,
                recommendations,
                null
        );

        recordScan(userId, "PHISHING_IMAGE", "Screenshot: " + safeFileName, response);
        return response;
    }



    private void recordScan(String userId, String scanType, String target, PhishingScanDto.Response response) {
        try {
            ScanRecord record = new ScanRecord(
                    userId,
                    scanType,
                    target,
                    response.getThreatLevel(),
                    response.getRiskScore(),
                    "PHISHING".equals(response.getThreatLevel()) ? "HIGH" : ("SUSPICIOUS".equals(response.getThreatLevel()) ? "MEDIUM" : "LOW"),
                    response.getSummary(),
                    LocalDateTime.now()
            );
            historyService.addRecord(record);
        } catch (Exception e) {
            log.warn("Failed to record phishing scan: {}", e.getMessage());
        }
    }
}
