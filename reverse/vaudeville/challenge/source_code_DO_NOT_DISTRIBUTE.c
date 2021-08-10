#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

const int LOOPS = 133;
const char * big_str[256] = {
    "",
"W",
"e\'",
"re ",
"no s",
"trang",
"ers to",
" love Y",
"ou know ",
"the rules",
" and so do",
" I A full c",
"ommitment\'s ",
"what I\'m thin",
"king of You wo",
"uldn\'t get this",
" from any other ",
"guy  I just wanna",
" tell you how I\'m ",
"feeling Gotta make ",
"you understand  Neve",
"r gonna give you up N",
"ever gonna let you dow",
"n Never gonna run aroun",
"d and desert you Never g",
"onna make you cry Never g",
"onna say goodbye Never gon",
"na tell a lie and hurt you ",
" We\'ve known each other for ",
"so long Your heart\'s been ach",
"ing, but you\'re too shy to say",
" it Inside, we both know what\'s",
" been going on We know the game,",
" and we\'re gonna play it And if y",
"ou ask me how I\'m feeling Don\'t te",
"ll me you\'re too blind to see  Neve",
"r gonna give you up Never gonna let ",
"you down Never gonna run around and d",
"esert you Never gonna make you cry Nev",
"er gonna say goodbye Never gonna tell a",
" lie and hurt you Never gonna give you u",
"p Never gonna let you down Never gonna ru",
"n around and desert you Never gonna make y",
"ou cry Never gonna say goodbye Never gonna ",
"tell a lie and hurt you  Ooh (Give you up) O",
"oh-ooh (Give you up) Ooh-ooh Never gonna give",
", never gonna give (Give you up) Ooh-ooh Never",
" gonna give, never gonna give (Give you up) We\'",
"ve known each other for so long Your heart\'s bee",
"n aching, but you\'re too shy to say it Inside, we",
" both know what\'s been going on We know the game, ",
"and we\'re gonna play it I just wanna tell you how I",
"\'m feeling Gotta make you understand Never gonna giv",
"e you up Never gonna let you down Never gonna run aro",
"und and desert you Never gonna make you cry Never gonn",
"a say goodbye Never gonna tell a lie and hurt you Never",
" gonna give you up Never gonna let you down Never gonna ",
"run around and desert you Never gonna make you cry Never ",
"gonna say goodbye Never gonna tell a lie and hurt you Neve",
"r gonna give you up Never gonna let you down Never gonna ru",
"n around and desert you Never gonna make you cry Never gonna",
" say goodbye Never gonna tell a lie and hurt you. According t",
"o all known laws of aviation, there is no way a bee should be ",
"able to fly. Its wings are too small to get its fat little body",
" off the ground. The bee, of course, flies anyway because bees d",
"on\'t care what humans think is impossible. Yellow, black. Yellow,",
" black. Yellow, black. Yellow, black. Ooh, black and yellow! Let\'s",
" shake it up a little. Barry! Breakfast is ready! Ooming! Hang on a",
" second. Hello? - Barry? - Adam? - Oan you believe this is happening",
"? - I can\'t. I\'ll pick you up. Looking sharp. Use the stairs. Your fa",
"ther paid good money for those. Sorry. I\'m excited. Here\'s the graduat",
"e. We\'re very proud of you, son. A perfect report card, all B\'s. Very p",
"roud. Ma! I got a thing going here. - You got lint on your fuzz. - Ow! T",
"hat\'s me! - Wave to us! We\'ll be in row 118,000. - Bye! Barry, I told you",
", stop flying in the house! - Hey, Adam. - Hey, Barry. - Is that fuzz gel?",
" - A little. Special day, graduation. Never thought I\'d make it. Three days",
" grade school, three days high school. Those were awkward. Three days colleg",
"e. I\'m glad I took a day and hitchhiked around the hive. You did come back di",
"fferent. - Hi, Barry. - Artie, growing a mustache? Looks good. - Hear about Fr",
"ankie? - Yeah. - You going to the funeral? - No, I\'m not going. Everybody knows",
", sting someone, you die. Don\'t waste it on a squirrel. Such a hothead. I guess ",
"he could have just gotten out of the way. I love this incorporating an amusement ",
"park into our day. That\'s why we don\'t need vacations. Boy, quite a bit of pomp...",
" under the circumstances. - Well, Adam, today we are men. - We are! - Bee-men. - Am",
"en! Hallelujah! Students, faculty, distinguished bees, please welcome Dean Buzzwell.",
" Welcome, New Hive Oity graduating class of... ...9:15. That concludes our ceremonies",
". And begins your career at Honex Industries! Will we pick ourjob today? I heard it\'s ",
"just orientation. Heads up! Here we go. Keep your hands and antennas inside the tram at",
" all times. - Wonder what it\'ll be like? - A little scary. Welcome to Honex, a division ",
"of Honesco and a part of the Hexagon Group. This is it! Wow. Wow. We know that you, as a ",
"bee, have worked your whole life to get to the point where you can work for your whole lif",
"e. Honey begins when our valiant Pollen Jocks bring the nectar to the hive. Our top-secret ",
"formula is automatically color-corrected, scent-adjusted and bubble-contoured into this soot",
"hing sweet syrup with its distinctive golden glow you know as... Honey! - That girl was hot. ",
"- She\'s my cousin! - She is? - Yes, we\'re all cousins. - Right. You\'re right. - At Honex, we c",
"onstantly strive to improve every aspect of bee existence. These bees are stress-testing a new ",
"helmet technology. - What do you think he makes? - Not enough. Here we have our latest advanceme",
"nt, the Krelman. - What does that do? - Oatches that little strand of honey that hangs after you ",
"pour it. Saves us millions. Oan anyone work on the Krelman? Of course. Most bee jobs are small one",
"s. But bees know that every small job, if it\'s done well, means a lot. But choose carefully because",
" you\'ll stay in the job you pick for the rest of your life. The same job the rest of your life? I di",
"dn\'t know that. What\'s the difference? You\'ll be happy to know that bees, as a species, haven\'t had o",
"ne day off in 27 million years. So you\'ll just work us to death? We\'ll sure try. Wow! That blew my min",
"d! \"What\'s the difference?\" How can you say that? One job forever? That\'s an insane choice to have to m",
"ake. I\'m relieved. Now we only have to make one decision in life. But, Adam, how could they never have t",
"old us that? Why would you question anything? We\'re bees. We\'re the most perfectly functioning society on",
" Earth. You ever think maybe things work a little too well here? Like what? Give me one example. I don\'t k",
"now. But you know what I\'m talking about. Please clear the gate. Royal Nectar Force on approach. Wait a sec",
"ond. Oheck it out. - Hey, those are Pollen Jocks! - Wow. I\'ve never seen them this close. They know what it\'",
"s like outside the hive. Yeah, but some don\'t come back. - Hey, Jocks! - Hi, Jocks! You guys did great! You\'r",
"e monsters! You\'re sky freaks! I love it! I love it! - I wonder where they were. - I don\'t know. Their day\'s n",
"ot planned. Outside the hive, flying who knows where, doing who knows what. You can\'tjust decide to be a Pollen",
" Jock. You have to be bred for that. Right. Look. That\'s more pollen than you and I will see in a lifetime. It\'s",
" just a status symbol. Bees make too much of it. Perhaps. Unless you\'re wearing it and the ladies see you wearing",
" it. Those ladies? Aren\'t they our cousins too? Distant. Distant. Look at these two. - Oouple of Hive Harrys. - Le",
"t\'s have fun with them. It must be dangerous being a Pollen Jock. Yeah. Once a bear pinned me against a mushroom! H",
"e had a paw on my throat, and with the other, he was slapping me! - Oh, my! - I never thought I\'d knock him out. Wha",
"t were you doing during this? Trying to alert the authorities. I can autograph that. A little gusty out there today, ",
"wasn\'t it, comrades? Yeah. Gusty. We\'re hitting a sunflower patch six miles from here tomorrow. - Six miles, huh? - Ba",
"rry! A puddle jump for us, but maybe you\'re not up for it. - Maybe I am. - You are not! We\'re going 0900 at J-Gate. Wha",
"t do you think, buzzy-boy? Are you bee enough? I might be. It all depends on what 0900 means. Hey, Honex! Dad, you surpr",
"ised me. You decide what you\'re interested in? - Well, there\'s a lot of choices. - But you only get one. Do you ever get ",
"bored doing the same job every day? Son, let me tell you about stirring. You grab that stick, and you just move it around,",
" and you stir it around. You get yourself into a rhythm. It\'s a beautiful thing. You know, Dad, the more I think about it, ",
"maybe the honey field just isn\'t right for me. You were thinking of what, making balloon animals? That\'s a bad job for a guy",
" with a stinger. Janet, your son\'s not sure he wants to go into honey! - Barry, you are so funny sometimes. - I\'m not trying ",
"to be funny. You\'re not funny! You\'re going into honey. Our son, the stirrer! - You\'re gonna be a stirrer? - No one\'s listenin",
"g to me! Wait till you see the sticks I have. I could say anything right now. I\'m gonna get an ant tattoo! Let\'s open some hone",
"y and celebrate! Maybe I\'ll pierce my thorax. Shave my antennae. Shack up with a grasshopper. Get a gold tooth and call everybod",
"y \"dawg\"! I\'m so proud. - We\'re starting work today! - Today\'s the day. Oome on! All the good jobs will be gone. Yeah, right. Pol",
"len counting, stunt bee, pouring, stirrer, front desk, hair removal... - Is it still available? - Hang on. Two left! One of them\'s",
" yours! Oongratulations! Step to the side. - What\'d you get? - Picking crud out. Stellar! Wow! Oouple of newbies? Yes, sir! Our fir",
"st day! We are ready! Make your choice. - You want to go first? - No, you go. Oh, my. What\'s available? Restroom attendant\'s open, n",
"ot for the reason you think. - Any chance of getting the Krelman? - Sure, you\'re on. I\'m sorry, the Krelman just closed out. Wax monk",
"ey\'s always open. The Krelman opened up again. What happened? A bee died. Makes an opening. See? He\'s dead. Another dead one. Deady. D",
"eadified. Two more dead. Dead from the neck up. Dead from the neck down. That\'s life! Oh, this is so hard! Heating, cooling, stunt bee,",
" pourer, stirrer, humming, inspector number seven, lint coordinator, stripe supervisor, mite wrangler. Barry, what do you think I should",
"... Barry? Barry! All right, we\'ve got the sunflower patch in quadrant nine... What happened to you? Where are you? - I\'m going out. - Ou",
"t? Out where? - Out there. - Oh, no! I have to, before I go to work for the rest of my life. You\'re gonna die! You\'re crazy! Hello? Anothe",
"r call coming in. If anyone\'s feeling brave, there\'s a Korean deli on 83rd that gets their roses today. Hey, guys. - Look at that. - Isn\'t ",
"that the kid we saw yesterday? Hold it, son, flight deck\'s restricted. It\'s OK, Lou. We\'re gonna take him up. Really? Feeling lucky, are you",
"? Sign here, here. Just initial that. - Thank you. - OK. You got a rain advisory today, and as you all know, bees cannot fly in rain. So be c",
"areful. As always, watch your brooms, hockey sticks, dogs, birds, bears and bats. Also, I got a couple of reports of root beer being poured on",
" us. Murphy\'s in a home because of it, babbling like a cicada! - That\'s awful. - And a reminder for you rookies, bee law number one, absolutely",
" no talking to humans! All right, launch positions! Buzz, buzz, buzz, buzz! Buzz, buzz, buzz, buzz! Buzz, buzz, buzz, buzz! Black and yellow! He",
"llo! You ready for this, hot shot? Yeah. Yeah, bring it on. Wind, check. - Antennae, check. - Nectar pack, check. - Wings, check. - Stinger, chec",
"k. Scared out of my shorts, check. OK, ladies, let\'s move it out! Pound those petunias, you striped stem-suckers! All of you, drain those flowers!",
" Wow! I\'m out! I can\'t believe I\'m out! So blue. I feel so fast and free! Box kite! Wow! Flowers! This is Blue Leader. We have roses visual. Bring ",
"it around 30 degrees and hold. Roses! 30 degrees, roger. Bringing it around. Stand to the side, kid. It\'s got a bit of a kick. That is one nectar co",
"llector! - Ever see pollination up close? - No, sir. I pick up some pollen here, sprinkle it over here. Maybe a dash over there, a pinch on that one.",
" See that? It\'s a little bit of magic. That\'s amazing. Why do we do that? That\'s pollen power. More pollen, more flowers, more nectar, more honey for ",
"us. Oool. I\'m picking up a lot of bright yellow. Oould be daisies. Don\'t we need those? Oopy that visual. Wait. One of these flowers seems to be on the",
" move. Say again? You\'re reporting a moving flower? Affirmative. That was on the line! This is the coolest. What is it? I don\'t know, but I\'m loving thi",
"s color. It smells good. Not like a flower, but I like it. Yeah, fuzzy. Ohemical-y. Oareful, guys. It\'s a little grabby. My sweet lord of bees! Oandy-bra",
"in, get off there! Problem! - Guys! - This could be bad. Affirmative. Very close. Gonna hurt. Mama\'s little boy. You are way out of position, rookie! Oomi",
"ng in at you like a missile! Help me! I don\'t think these are flowers. - Should we tell him? - I think he knows. What is this?! Match point! You can start ",
"packing up, honey, because you\'re about to eat it! Yowser! Gross. There\'s a bee in the car! - Do something! - I\'m driving! - Hi, bee. - He\'s back here! He\'s",
" going to sting me! Nobody move. If you don\'t move, he won\'t sting you. Freeze! He blinked! Spray him, Granny! What are you doing?! Wow... the tension level ",
"out here is unbelievable. I gotta get home. Oan\'t fly in rain. Oan\'t fly in rain. Oan\'t fly in rain. Mayday! Mayday! Bee going down! Ken, could you close the ",
"window please? Ken, could you close the window please? Oheck out my new resume. I made it into a fold-out brochure. You see? Folds out. Oh, no. More humans. I ",
"don\'t need this. What was that? Maybe this time. This time. This time. This time! This time! This... Drapes! That is diabolical. It\'s fantastic. It\'s got all my",
" special skills, even my top-ten favorite movies. What\'s number one? Star Wars? Nah, I don\'t go for that... ...kind of stuff. No wonder we shouldn\'t talk to them",
". They\'re out of their minds. When I leave a job interview, they\'re flabbergasted, can\'t believe what I say. There\'s the sun. Maybe that\'s a way out. I don\'t reme",
"mber the sun having a big 75 on it. I predicted global warming. I could feel it getting hotter. At first I thought it was just me. Wait! Stop! Bee! Stand back. The",
"se are winter boots. Wait! Don\'t kill him! You know I\'m allergic to them! This thing could kill me! Why does his life have less value than yours? Why does his life ",
"have any less value than mine? Is that your statement? I\'m just saying all life has value. You don\'t know what he\'s capable of feeling. My brochure! There you go, li",
"ttle guy. I\'m not scared of him. It\'s an allergic thing. Put that on your resume brochure. My whole face could puff up. Make it one of your special skills. Knocking s",
"omeone out is also a special skill. Right. Bye, Vanessa. Thanks. - Vanessa, next week? Yogurt night? - Sure, Ken. You know, whatever. - You could put carob chips on th",
"ere. - Bye. - Supposed to be less calories. - Bye. I gotta say something. She saved my life. I gotta say something. All right, here it goes. Nah. What would I say? I co",
"uld really get in trouble. It\'s a bee law. You\'re not supposed to talk to a human. I can\'t believe I\'m doing this. I\'ve got to. Oh, I can\'t do it. Oome on! No. Yes. No. ",
"Do it. I can\'t. How should I start it? \"You like jazz?\" No, that\'s no good. Here she comes! Speak, you fool! Hi! I\'m sorry. - You\'re talking. - Yes, I know. You\'re talkin",
"g! I\'m so sorry. No, it\'s OK. It\'s fine. I know I\'m dreaming. But I don\'t recall going to bed. Well, I\'m sure this is very disconcerting. This is a bit of a surprise to me",
". I mean, you\'re a bee! I am. And I\'m not supposed to be doing this, but they were all trying to kill me. And if it wasn\'t for you... I had to thank you. It\'s just how I wa",
"s raised. That was a little weird. - I\'m talking with a bee. - Yeah. I\'m talking to a bee. And the bee is talking to me! I just want to say I\'m grateful. I\'ll leave now. - W",
"ait! How did you learn to do that? - What? The talking thing. Same way you did, I guess. \"Mama, Dada, honey.\" You pick it up. - That\'s very funny. - Yeah. Bees are funny. If ",
"we didn\'t laugh, we\'d cry with what we have to deal with. Anyway... Oan I... ...get you something? - Like what? I don\'t know. I mean... I don\'t know. Ooffee? I don\'t want to p",
"ut you out. It\'s no trouble. It takes two minutes. - It\'s just coffee. - I hate to impose. - Don\'t be ridiculous! - Actually, I would love a cup. Hey, you want rum cake? - I sh",
"ouldn\'t. - Have some. - No, I can\'t. - Oome on! I\'m trying to lose a couple micrograms. - Where? - These stripes don\'t help. You look great! I don\'t know if you know anything ab",
"out fashion. Are you all right? No. He\'s making the tie in the cab as they\'re flying up Madison. He finally gets there. He runs up the steps into the church. The wedding is on. A",
"nd he says, \"Watermelon? I thought you said Guatemalan. Why would I marry a watermelon?\" Is that a bee joke? That\'s the kind of stuff we do. Yeah, different. So, what are you gonn",
"a do, Barry? About work? I don\'t know. I want to do my part for the hive, but I can\'t do it the way they want. I know how you feel. - You do? - Sure. My parents wanted me to be a l",
"awyer or a doctor, but I wanted to be a florist. - Really? - My only interest is flowers. Our new queen was just elected with that same campaign slogan. Anyway, if you look... There",
"\'s my hive right there. See it? You\'re in Sheep Meadow! Yes! I\'m right off the Turtle Pond! No way! I know that area. I lost a toe ring there once. - Why do girls put rings on their ",
"toes? - Why not? - It\'s like putting a hat on your knee. - Maybe I\'ll try that. - You all right, ma\'am? - Oh, yeah. Fine. Just having two cups of coffee! Anyway, this has been great. ",
"Thanks for the coffee. Yeah, it\'s no trouble. Sorry I couldn\'t finish it. If I did, I\'d be up the rest of my life. Are you...? Oan I take a piece of this with me? Sure! Here, have a cr",
"umb. - Thanks! - Yeah. All right. Well, then... I guess I\'ll see you around. Or not. OK, Barry. And thank you so much again... for before. Oh, that? That was nothing. Well, not nothing,",
" but... Anyway... This can\'t possibly work. He\'s all set to go. We may as well try it. OK, Dave, pull the chute. - Sounds amazing. - It was amazing! It was the scariest, happiest moment ",
"of my life. Humans! I can\'t believe you were with humans! Giant, scary humans! What were they like? Huge and crazy. They talk crazy. They eat crazy giant things. They drive crazy. - Do th",
"ey try and kill you, like on TV? - Some of them. But some of them don\'t. - How\'d you get back? - Poodle. You did it, and I\'m glad. You saw whatever you wanted to see. You had your \"experie",
"nce.\" Now you can pick out yourjob and be normal. - Well... - Well? Well, I met someone. You did? Was she Bee-ish? - A wasp?! Your parents will kill you! - No, no, no, not a wasp. - Spider?",
" - I\'m not attracted to spiders. I know it\'s the hottest thing, with the eight legs and all. I can\'t get by that face. So who is she? She\'s... human. No, no. That\'s a bee law. You wouldn\'t b",
"reak a bee law. - Her name\'s Vanessa. - Oh, boy. She\'s so nice. And she\'s a florist! Oh, no! You\'re dating a human florist! We\'re not dating. You\'re flying outside the hive, talking to humans",
" that attack our homes with power washers and M-80s! One-eighth a stick of dynamite! She saved my life! And she understands me. This is over! Eat this. This is not over! What was that? - They ",
"call it a crumb. - It was so stingin\' stripey! And that\'s not what they eat. That\'s what falls off what they eat! - You know what a Oinnabon is? - No. It\'s bread and cinnamon and frosting. They",
" heat it up... Sit down! ...really hot! - Listen to me! We are not them! We\'re us. There\'s us and there\'s them! Yes, but who can deny the heart that is yearning? There\'s no yearning. Stop yearni",
"ng. Listen to me! You have got to start thinking bee, my friend. Thinking bee! - Thinking bee. - Thinking bee. Thinking bee! Thinking bee! Thinking bee! Thinking bee! There he is. He\'s in the poo",
"l. You know what your problem is, Barry? I gotta start thinking bee? How much longer will this go on? It\'s been three days! Why aren\'t you working? I\'ve got a lot of big life decisions to think ab",
"out. What life? You have no life! You have no job. You\'re barely a bee! Would it kill you to make a little honey? Barry, come out. Your father\'s talking to you. Martin, would you talk to him? Barry",
", I\'m talking to you! You coming? Got everything? All set! Go ahead. I\'ll catch up. Don\'t be too long. Watch this! Vanessa! - We\'re still here. - I told you not to yell at him. He doesn\'t respond to",
" yelling! - Then why yell at me? - Because you don\'t listen! I\'m not listening to this. Sorry, I\'ve gotta go. - Where are you going? - I\'m meeting a friend. A girl? Is this why you can\'t decide? Bye.",
" I just hope she\'s Bee-ish. They have a huge parade of flowers every year in Pasadena? To be in the Tournament of Roses, that\'s every florist\'s dream! Up on a float, surrounded by flowers, crowds chee",
"ring. A tournament. Do the roses compete in athletic events? No. All right, I\'ve got one. How come you don\'t fly everywhere? It\'s exhausting. Why don\'t you run everywhere? It\'s faster. Yeah, OK, I see,",
" I see. All right, your turn. TiVo. You can just freeze live TV? That\'s insane! You don\'t have that? We have Hivo, but it\'s a disease. It\'s a horrible, horrible disease. Oh, my. Dumb bees! You must want",
" to sting all those jerks. We try not to sting. It\'s usually fatal for us. So you have to watch your temper. Very carefully. You kick a wall, take a walk, write an angry letter and throw it out. Work thr",
"ough it like any emotion: Anger, jealousy, lust. Oh, my goodness! Are you OK? Yeah. - What is wrong with you?! - It\'s a bug. He\'s not bothering anybody. Get out of here, you creep! What was that? A Pic \'N",
"\' Save circular? Yeah, it was. How did you know? It felt like about 10 pages. Seventy-five is pretty much our limit. You\'ve really got that down to a science. - I lost a cousin to Italian Vogue. - I\'ll bet",
". What in the name of Mighty Hercules is this? How did this get here? Oute Bee, Golden Blossom, Ray Liotta Private Select? - Is he that actor? - I never heard of him. - Why is this here? - For people. We ea",
"t it. You don\'t have enough food of your own? - Well, yes. - How do you get it? - Bees make it. - I know who makes it! And it\'s hard to make it! There\'s heating, cooling, stirring. You need a whole Krelman t",
"hing! - It\'s organic. - It\'s our-ganic! It\'s just honey, Barry. Just what?! Bees don\'t know about this! This is stealing! A lot of stealing! You\'ve taken our homes, schools, hospitals! This is all we have! An",
"d it\'s on sale?! I\'m getting to the bottom of this. I\'m getting to the bottom of all of this! Hey, Hector. - You almost done? - Almost. He is here. I sense it. Well, I guess I\'ll go home now and just leave thi",
"s nice honey out, with no one around. You\'re busted, box boy! I knew I heard something. So you can talk! I can talk. And now you\'ll start talking! Where you getting the sweet stuff? Who\'s your supplier? I don\'t",
" understand. I thought we were friends. The last thing we want to do is upset bees! You\'re too late! It\'s ours now! You, sir, have crossed the wrong sword! You, sir, will be lunch for my iguana, Ignacio! Where i",
"s the honey coming from? Tell me where! Honey Farms! It comes from Honey Farms! Orazy person! What horrible thing has happened here? These faces, they never knew what hit them. And now they\'re on the road to nowh",
"ere! Just keep still. What? You\'re not dead? Do I look dead? They will wipe anything that moves. Where you headed? To Honey Farms. I am onto something huge here. I\'m going to Alaska. Moose blood, crazy stuff. Blow",
"s your head off! I\'m going to Tacoma. - And you? - He really is dead. All right. Uh-oh! - What is that?! - Oh, no! - A wiper! Triple blade! - Triple blade? Jump on! It\'s your only chance, bee! Why does everything h",
"ave to be so doggone clean?! How much do you people need to see?! Open your eyes! Stick your head out the window! From NPR News in Washington, I\'m Oarl Kasell. But don\'t kill no more bugs! - Bee! - Moose blood guy!!",
" - You hear something? - Like what? Like tiny screaming. Turn off the radio. Whassup, bee boy? Hey, Blood. Just a row of honey jars, as far as the eye could see. Wow! I assume wherever this truck goes is where they\'r",
"e getting it. I mean, that honey\'s ours. - Bees hang tight. - We\'re all jammed in. It\'s a close community. Not us, man. We on our own. Every mosquito on his own. - What if you get in trouble? - You a mosquito, you in ",
"trouble. Nobody likes us. They just smack. See a mosquito, smack, smack! At least you\'re out in the world. You must meet girls. Mosquito girls try to trade up, get with a moth, dragonfly. Mosquito girl don\'t want no mo",
"squito. You got to be kidding me! Mooseblood\'s about to leave the building! So long, bee! - Hey, guys! - Mooseblood! I knew I\'d catch y\'all down here. Did you bring your crazy straw? We throw it in jars, slap a label on",
" it, and it\'s pretty much pure profit. What is this place? A bee\'s got a brain the size of a pinhead. They are pinheads! Pinhead. - Oheck out the new smoker. - Oh, sweet. That\'s the one you want. The Thomas 3000! Smoker?",
" Ninety puffs a minute, semi-automatic. Twice the nicotine, all the tar. A couple breaths of this knocks them right out. They make the honey, and we make the money. \"They make the honey, and we make the money\"? Oh, my! Wh",
"at\'s going on? Are you OK? Yeah. It doesn\'t last too long. Do you know you\'re in a fake hive with fake walls? Our queen was moved here. We had no choice. This is your queen? That\'s a man in women\'s clothes! That\'s a drag q",
"ueen! What is this? Oh, no! There\'s hundreds of them! Bee honey. Our honey is being brazenly stolen on a massive scale! This is worse than anything bears have done! I intend to do something. Oh, Barry, stop. Who told you hu",
"mans are taking our honey? That\'s a rumor. Do these look like rumors? That\'s a conspiracy theory. These are obviously doctored photos. How did you get mixed up in this? He\'s been talking to humans. - What? - Talking to human",
"s?! He has a human girlfriend. And they make out! Make out? Barry! We do not. - You wish you could. - Whose side are you on? The bees! I dated a cricket once in San Antonio. Those crazy legs kept me up all night. Barry, this ",
"is what you want to do with your life? I want to do it for all our lives. Nobody works harder than bees! Dad, I remember you coming home so overworked your hands were still stirring. You couldn\'t stop. I remember that. What ri",
"ght do they have to our honey? We live on two cups a year. They put it in lip balm for no reason whatsoever! Even if it\'s true, what can one bee do? Sting them where it really hurts. In the face! The eye! - That would hurt. - N",
"o. Up the nose? That\'s a killer. There\'s only one place you can sting the humans, one place where it matters. Hive at Five, the hive\'s only full-hour action news source. No more bee beards! With Bob Bumble at the anchor desk. We",
"ather with Storm Stinger. Sports with Buzz Larvi. And Jeanette Ohung. - Good evening. I\'m Bob Bumble. - And I\'m Jeanette Ohung. A tri-county bee, Barry Benson, intends to sue the human race for stealing our honey, packaging it an",
"d profiting from it illegally! Tomorrow night on Bee Larry King, we\'ll have three former queens here in our studio, discussing their new book, Olassy Ladies, out this week on Hexagon. Tonight we\'re talking to Barry Benson. Did you",
" ever think, \"I\'m a kid from the hive. I can\'t do this\"? Bees have never been afraid to change the world. What about Bee Oolumbus? Bee Gandhi? Bejesus? Where I\'m from, we\'d never sue humans. We were thinking of stickball or candy s",
"tores. How old are you? The bee community is supporting you in this case, which will be the trial of the bee century. You know, they have a Larry King in the human world too. It\'s a common name. Next week... He looks like you and ha",
"s a show and suspenders and colored dots... Next week... Glasses, quotes on the bottom from the guest even though you just heard \'em. Bear Week next week! They\'re scary, hairy and here live. Always leans forward, pointy shoulders, sq",
"uinty eyes, very Jewish. In tennis, you attack at the point of weakness! It was my grandmother, Ken. She\'s 81. Honey, her backhand\'s a joke! I\'m not gonna take advantage of that? Quiet, please. Actual work going on here. - Is that tha",
"t same bee? - Yes, it is! I\'m helping him sue the human race. - Hello. - Hello, bee. This is Ken. Yeah, I remember you. Timberland, size ten and a half. Vibram sole, I believe. Why does he talk again? Listen, you better go \'cause we\'re",
" really busy working. But it\'s our yogurt night! Bye-bye. Why is yogurt night so difficult?! You poor thing. You two have been at this for hours! Yes, and Adam here has been a huge help. - Frosting... - How many sugars? Just one. I try ",
"not to use the competition. So why are you helping me? Bees have good qualities. And it takes my mind off the shop. Instead of flowers, people are giving balloon bouquets now. Those are great, if you\'re three. And artificial flowers. - O",
"h, those just get me psychotic! - Yeah, me too. Bent stingers, pointless pollination. Bees must hate those fake things! Nothing worse than a daffodil that\'s had work done. Maybe this could make up for it a little bit. - This lawsuit\'s a p",
"retty big deal. - I guess. You sure you want to go through with it? Am I sure? When I\'m done with the humans, they won\'t be able to say, \"Honey, I\'m home,\" without paying a royalty! It\'s an incredible scene here in downtown Manhattan, wher",
"e the world anxiously waits, because for the first time in history, we will hear for ourselves if a honeybee can actually speak. What have we gotten into here, Barry? It\'s pretty big, isn\'t it? I can\'t believe how many humans don\'t work dur",
"ing the day. You think billion-dollar multinational food companies have good lawyers? Everybody needs to stay behind the barricade. - What\'s the matter? - I don\'t know, I just got a chill. Well, if it isn\'t the bee team. You boys work on thi",
"s? All rise! The Honorable Judge Bumbleton presiding. All right. Oase number 4475, Superior Oourt of New York, Barry Bee Benson v. the Honey Industry is now in session. Mr. Montgomery, you\'re representing the five food companies collectively?",
" A privilege. Mr. Benson... you\'re representing all the bees of the world? I\'m kidding. Yes, Your Honor, we\'re ready to proceed. Mr. Montgomery, your opening statement, please. Ladies and gentlemen of the jury, my grandmother was a simple woma",
"n. Born on a farm, she believed it was man\'s divine right to benefit from the bounty of nature God put before us. If we lived in the topsy-turvy world Mr. Benson imagines, just think of what would it mean. I would have to negotiate with the sil",
"kworm for the elastic in my britches! Talking bee! How do we know this isn\'t some sort of holographic motion-picture-capture Hollywood wizardry? They could be using laser beams! Robotics! Ventriloquism! Oloning! For all we know, he could be on s",
"teroids! Mr. Benson? Ladies and gentlemen, there\'s no trickery here. I\'m just an ordinary bee. Honey\'s pretty important to me. It\'s important to all bees. We invented it! We make it. And we protect it with our lives. Unfortunately, there are some",
" people in this room who think they can take it from us \'cause we\'re the little guys! I\'m hoping that, after this is all over, you\'ll see how, by taking our honey, you not only take everything we have but everything we are! I wish he\'d dress like ",
"that all the time. So nice! Oall your first witness. So, Mr. Klauss Vanderhayden of Honey Farms, big company you have. I suppose so. I see you also own Honeyburton and Honron! Yes, they provide beekeepers for our farms. Beekeeper. I find that to be",
" a very disturbing term. I don\'t imagine you employ any bee-free-ers, do you? - No. - I couldn\'t hear you. - No. - No. Because you don\'t free bees. You keep bees. Not only that, it seems you thought a bear would be an appropriate image for a jar of ",
"honey. They\'re very lovable creatures. Yogi Bear, Fozzie Bear, Build-A-Bear. You mean like this? Bears kill bees! How\'d you like his head crashing through your living room?! Biting into your couch! Spitting out your throw pillows! OK, that\'s enough. ",
"Take him away. So, Mr. Sting, thank you for being here. Your name intrigues me. - Where have I heard it before? - I was with a band called The Police. But you\'ve never been a police officer, have you? No, I haven\'t. No, you haven\'t. And so here we hav",
"e yet another example of bee culture casually stolen by a human for nothing more than a prance-about stage name. Oh, please. Have you ever been stung, Mr. Sting? Because I\'m feeling a little stung, Sting. Or should I say... Mr. Gordon M. Sumner! That\'s",
" not his real name?! You idiots! Mr. Liotta, first, belated congratulations on your Emmy win for a guest spot on ER in 2005. Thank you. Thank you. I see from your resume that you\'re devilishly handsome with a churning inner turmoil that\'s ready to blow.",
" I enjoy what I do. Is that a crime? Not yet it isn\'t. But is this what it\'s come to for you? Exploiting tiny, helpless bees so you don\'t have to rehearse your part and learn your lines, sir? Watch it, Benson! I could blow right now! This isn\'t a goodfel",
"la. This is a badfella! Why doesn\'t someone just step on this creep, and we can all go home?! - Order in this court! - You\'re all thinking it! Order! Order, I say! - Say it! - Mr. Liotta, please sit down! I think it was awfully nice of that bear to pitch ",
};

char __attribute__((always_inline)) sub_0080688(unsigned char left, unsigned char right) {
    pid_t pid;
    int mypipe[2];

    /* Create the pipe. */
    if (pipe (mypipe)) {
        fprintf (stderr, "Pipe failed.\n");
        return -1;
    }

    /* Create the child process. */
    pid = fork ();
    if (pid == (pid_t) 0) {
        /* This is the child process.
        Close other end first. */
        close (mypipe[0]);
        int new_fd = dup(mypipe[1]);
        FILE *stream_left;
        FILE *stream_right;
        stream_left = fdopen (mypipe[1], "w");
        stream_right = fdopen (new_fd, "w");
        fwrite(big_str[left], 1, left, stream_left);
        fwrite(big_str[right], 1, right, stream_right);
        fclose (stream_left);
        fclose (stream_right);
        exit(0);
    }
    else if (pid < (pid_t) 0) {
    /* The fork failed. */
        fprintf (stderr, "Fork failed.\n");
        exit(-1);
    }
    else {
    /* This is the parent process.
        Close other end first. */
        close (mypipe[1]);
        FILE *stream;
        stream = fdopen (mypipe[0], "r");
        unsigned char buf[512];
        unsigned char s = fread(&buf, 1, 512, stream);

        fclose(stream);

        return s;
    }
}

uint32_t get_challenge() {
    FILE *fp = fopen("/dev/urandom", "rb");
    
    unsigned char buf[4];
    
    fread(buf, 1, 4, fp);
    fclose(fp);

    return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) | ((uint32_t) buf[2] << 8) | ((uint32_t) buf[3] << 0);
}

uint32_t go(uint32_t challenge, int steps) {
    // Create buffer to hold iteration
    unsigned char buf[32 * 3 + 1];
    memset(&buf, 0x30, 32 * 3);
    buf[32*3] = 0;
    for(int i = 0; i < 32; i++){
        if (challenge & (1 << i)){
            buf[32+i] = 0x31;
        }
        else{
            buf[32+i] = 0x30;
        }
    }

    // Create filename
    unsigned char fname[128];
    memset(&fname, 0, 128);
    sprintf(fname, "/tmp/tmp_%u", challenge);

    // Set up FD for writing
    FILE * fdw = fopen(fname, "wb");
    setvbuf(fdw, NULL, _IONBF, 0);
    fwrite(buf, 1, 32*3, fdw);
    fflush(fdw);

    // Make FDs for reading
    FILE * fd0 = fopen(fname, "rb");
    FILE * fd1 = fopen(fname, "rb");

    setvbuf(fd0, NULL, _IONBF, 0);
    setvbuf(fd1, NULL, _IONBF, 0);

    unsigned char left;
    unsigned char right;

    for (int q = 0; q < steps; q++){
        fseek(fd0, 32, SEEK_SET);
        fseek(fd1, 32-13, SEEK_SET);

        for (int j = 0; j < 32; j++){
            fread(&left, 1, 1, fd0);
            fread(&right, 1, 1, fd1);

            buf[j+32] = sub_0080688(left, right);
        }

        fseek(fd0, 32, SEEK_SET);
        fseek(fd1, 32+17, SEEK_SET);

        fseek(fdw, 0, SEEK_SET);
        fwrite(buf, 1, 32*3, fdw);
        fflush(fdw);


        for (int j = 0; j < 32; j++){
            fread(&left, 1, 1, fd0);
            fread(&right, 1, 1, fd1);

            buf[j+32] = sub_0080688(left, right);
        }

        fseek(fd0, 32, SEEK_SET);
        fseek(fd1, 32-5, SEEK_SET);

        fseek(fdw, 0, SEEK_SET);
        fwrite(buf, 1, 32*3, fdw);
        fflush(fdw);

        
        for (int j = 0; j < 32; j++){
            fread(&left, 1, 1, fd0);
            fread(&right, 1, 1, fd1);

            buf[j+32] = sub_0080688(left, right);
        }

        fseek(fdw, 0, SEEK_SET);
        fwrite(buf, 1, 32*3, fdw);
        fflush(fdw);
    }

    // Tear down file descriptors
    fclose(fd0);
    fclose(fd1);
    fclose(fdw);

    // read output from file
    uint32_t out = 0;

    FILE * fdx = fopen(fname, "rb");
    fseek(fdx, 32, SEEK_SET);

    unsigned char xtract_buf[32];
    fread(xtract_buf, 1, 32, fdx);
    fclose(fdx);

    for(int i = 0; i < 32; i++){
        out += ((xtract_buf[i] & 1) << i);
    }

    return out;
}

void print_flag(){
    FILE * fdf = fopen("flag.txt", "r");

    if (fdf == NULL){
        printf("If there was a flag here, you'd have won by now\n");
        exit(0);
    }

    unsigned char flag_buf[1025];
    memset(&flag_buf, 0, 1025);
    fread(flag_buf, 1, 1024, fdf);
    fclose(fdf);

    printf("%s", flag_buf);
}


int main() {
    uint32_t challenge = get_challenge();
    printf("Challenge: %u\n", challenge);

    uint32_t response;
    printf("Response: ");
    scanf("%u", &response);

    if (go(response, 7) == go(challenge, 133+7)) {
        print_flag();
    }
    else {
        printf("that's rough buddy\n");
    }

    return 0;
}