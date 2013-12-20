module ECrypt where

import           Crypto.Cipher.Salsa20          as S
import           Data.Bits
import           Data.ByteString                as BS hiding (map, reverse)
import           Data.ByteString.Lazy           as LBS hiding (map, reverse)
import           Data.Char
import           Data.Int
import           Data.Maybe
import           Foreign.Storable
import           Test.Framework                 as F
import           Test.Framework.Providers.HUnit
import           Test.HUnit                     as U

readHex :: (Storable a) => String -> a
readHex = fst . fromJust . readBinary . hexToByteString

hexToByteString :: String -> BS.ByteString
hexToByteString = BS.unfoldr convert
    where
        convert (a:b:xs) = Just $ (fromIntegral $ (digitToInt a) `shiftL` 4 + (digitToInt b), xs)
        convert (a:_) = error "Bytestring literal length should be even."
        convert [] = Nothing

keystreamToBytestring :: Keystream -> LBS.ByteString
keystreamToBytestring = fromChunks . go
    where
        go (Keystream block keystream) = writeBinary block : go keystream

testVector :: (Storable key) => Expand key -> String -> String -> String -> [((Int64, Int64), String)] -> F.Test
testVector f name key iv = testGroup name . map testSection
    where
        stream = keystream f (readHex key) (readHex iv) (SeqNum 0)
        testSection (section@(from, to), excepted) = testCase ("section " ++ show section) $ actual @=? fromChunks [hexToByteString excepted]
            where
                actual = LBS.take (to - from + 1) $ LBS.drop from $ keystreamToBytestring stream

eCrypt128 :: F.Test
eCrypt128 = testGroup "eCrypt128"
    [ testVector128 "Set 1, vector#  0"  "80000000000000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "4DFA5E481DA23EA09A31022050859936"
                                      ++ "DA52FCEE218005164F267CB65F5CFD7F"
                                      ++ "2B4F97E0FF16924A52DF269515110A07"
                                      ++ "F9E460BC65EF95DA58F740B7D1DBB0AA" )
                          , ((192, 255), "DA9C1581F429E0A00F7D67E23B730676"
                                      ++ "783B262E8EB43A25F55FB90B3E753AEF"
                                      ++ "8C6713EC66C51881111593CCB3E8CB8F"
                                      ++ "8DE124080501EEEB389C4BCB6977CF95" )
                          , ((256, 319), "7D5789631EB4554400E1E025935DFA7B"
                                      ++ "3E9039D61BDC58A8697D36815BF1985C"
                                      ++ "EFDF7AE112E5BB81E37ECF0616CE7147"
                                      ++ "FC08A93A367E08631F23C03B00A8DA2F" )
                          , ((448, 511), "B375703739DACED4DD4059FD71C3C47F"
                                      ++ "C2F9939670FAD4A46066ADCC6A564578"
                                      ++ "3308B90FFB72BE04A6B147CBE38CC0C3"
                                      ++ "B9267C296A92A7C69873F9F263BE9703" )
                          ]
    , testVector128 "Set 1, vector#  9"  "00400000000000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "0471076057830FB99202291177FBFE5D"
                                      ++ "38C888944DF8917CAB82788B91B53D1C"
                                      ++ "FB06D07A304B18BB763F888A61BB6B75"
                                      ++ "5CD58BEC9C4CFB7569CB91862E79C459" )
                          , ((192, 255), "D1D7E97556426E6CFC21312AE3811425"
                                      ++ "9E5A6FB10DACBD88E4354B0472556935"
                                      ++ "2B6DA5ACAFACD5E266F9575C2ED8E6F2"
                                      ++ "EFE4B4D36114C3A623DD49F4794F865B" )
                          , ((256, 319), "AF06FAA82C73291231E1BD916A773DE1"
                                      ++ "52FD2126C40A10C3A6EB40F22834B8CC"
                                      ++ "68BD5C6DBD7FC1EC8F34165C517C0B63"
                                      ++ "9DB0C60506D3606906B8463AA0D0EC2F" )
                          , ((448, 511), "AB3216F1216379EFD5EC589510B8FD35"
                                      ++ "014D0AA0B613040BAE63ECAB90A9AF79"
                                      ++ "661F8DA2F853A5204B0F8E72E9D9EB4D"
                                      ++ "BA5A4690E73A4D25F61EE7295215140C" )
                          ]
    , testVector128 "Set 1, vector#  18" "00002000000000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "BACFE4145E6D4182EA4A0F59D4076C7E"
                                      ++ "83FFD17E7540E5B7DE70EEDDF9552006"
                                      ++ "B291B214A43E127EED1DA1540F33716D"
                                      ++ "83C3AD7D711CD03251B78B2568F2C844" )
                          , ((192, 255), "56824347D03D9084ECCF358A0AE410B9"
                                      ++ "4F74AE7FAD9F73D2351E0A44DF127434"
                                      ++ "3ADE372BDA2971189623FD1EAA4B723D"
                                      ++ "76F5B9741A3DDC7E5B3E8ED4928EF421" )
                          , ((256, 319), "999F4E0F54C62F9211D4B1F1B79B227A"
                                      ++ "FB3116C9CF9ADB9715DE856A8EB31084"
                                      ++ "71AB40DFBF47B71389EF64C20E1FFDCF"
                                      ++ "018790BCE8E9FDC46527FE1545D3A6EA" )
                          , ((448, 511), "76F1B87E93EB9FEFEC3AED69210FE4AB"
                                      ++ "2ED577DECE01A75FD364CD1CD7DE1027"
                                      ++ "5A002DDBC494EE8350E8EEC1D8D6925E"
                                      ++ "FD6FE7EA7F610512F1F0A83C8949AEB1" )
                          ]
    , testVector128 "Set 1, vector#  27" "00000010000000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "24F4E317B675336E68A8E2A3A04CA967"
                                      ++ "AB96512ACBA2F832015E9BE03F08830F"
                                      ++ "CF32E93D14FFBD2C901E982831ED8062"
                                      ++ "21D7DC8C32BBC8E056F21BF9BDDC8020" )
                          , ((192, 255), "E223DE7299E51C94623F8EAD3A6DB045"
                                      ++ "4091EE2B54A498F98690D7D84DB7EFD5"
                                      ++ "A2A8202435CAC1FB34C842AEECF643C6"
                                      ++ "3054C424FAC5A632502CD3146278498A" )
                          , ((256, 319), "5A111014076A6D52E94C364BD7311B64"
                                      ++ "411DE27872FC8641D92C9D811F2B5185"
                                      ++ "94935F959D064A9BE806FAD06517819D"
                                      ++ "2321B248E1F37E108E3412CE93FA8970" )
                          , ((448, 511), "8A9AB11BD5360D8C7F34887982B3F658"
                                      ++ "6C34C1D6CB49100EA5D09A24C6B835D5"
                                      ++ "77C1A1C776902D785CB5516D74E87480"
                                      ++ "79878FDFDDF0126B1867E762546E4D72" )
                          ]
    , testVector128 "Set 1, vector#  36" "00000000080000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "9907DB5E2156427AD15B167BEB0AD445"
                                      ++ "452478AFEE3CF71AE1ED8EAF43E001A1"
                                      ++ "C8199AF9CFD88D2B782AA2F39845A26A"
                                      ++ "7AC54E5BE15DB7BDFBF873E16BC05A1D" )
                          , ((192, 255), "EBA0DCC03E9EB60AE1EE5EFE3647BE45"
                                      ++ "6E66733AA5D6353447981184A05F0F0C"
                                      ++ "B0AD1CB630C35DC253DE3FEBD10684CA"
                                      ++ "DBA8B4B85E02B757DED0FEB1C31D71A3" )
                          , ((256, 319), "BD24858A3DB0D9E552345A3C3ECC4C69"
                                      ++ "BBAE4901016A944C0D7ECCAAB9027738"
                                      ++ "975EEA6A4240D94DA183A74D649B789E"
                                      ++ "24A0849E26DC367BDE4539ADCCF0CAD8" )
                          , ((448, 511), "EE20675194FA404F54BAB7103F6821C1"
                                      ++ "37EE2347560DC31D338B01026AB6E571"
                                      ++ "65467215315F06360D85F3C5FE7A359E"
                                      ++ "80CBFE735F75AA065BC18EFB2829457D" )
                          ]
    , testVector128 "Set 1, vector# 45"  "00000000000400000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "A59CE982636F2C8C912B1E8105E2577D"
                                      ++ "9C86861E61FA3BFF757D74CB9EDE6027"
                                      ++ "D7D6DE775643FAF5F2C04971BDCB56E6"
                                      ++ "BE8144366235AC5E01C1EDF8512AF78B" )
                          , ((192, 255), "DF8F13F1059E54DEF681CD554439BAB7"
                                      ++ "24CDE604BE5B77D85D2829B3EB137F4F"
                                      ++ "2466BEADF4D5D54BA4DC36F1254BEC4F"
                                      ++ "B2B367A59EA6DDAC005354949D573E68" )
                          , ((256, 319), "B3F542ECBAD4ACA0A95B31D281B930E8"
                                      ++ "021993DF5012E48A333316E712C4E19B"
                                      ++ "58231AAE7C90C91C9CC135B12B490BE4"
                                      ++ "2CF9C9A2727621CA81B2C3A081716F76" )
                          , ((448, 511), "F64A6449F2F13030BE554DB00D24CD50"
                                      ++ "A89F80CCFE97435EBF0C49EB08747BF7"
                                      ++ "B2C89BE612629F231C1B3398D8B4CC3F"
                                      ++ "35DBECD1CF1CFDFDECD481B72A51276A" )
                          ]
    , testVector128 "Set 1, vector# 54"  "00000000000002000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "7A8131B777F7FBFD33A06E396FF32D7D"
                                      ++ "8C3CEEE9573F405F98BD6083FE57BAB6"
                                      ++ "FC87D5F34522D2440F649741D9F87849"
                                      ++ "BC8751EF432DEE5DCC6A88B34B6A1EA9" )
                          , ((192, 255), "6573F813310565DB22219984E0919445"
                                      ++ "9E5BB8613237F012EBB8249666582ACA"
                                      ++ "751ED59380199117DDB29A5298F95FF0"
                                      ++ "65D271AB66CF6BC6CDE0EA5FC4D304EB" )
                          , ((256, 319), "0E65CB6944AFBD84F5B5D00F307402B8"
                                      ++ "399BF02852ED2826EA9AA4A55FB56DF2"
                                      ++ "A6B83F7F228947DFAB2E0B10EAAA09D7"
                                      ++ "5A34F165ECB4D06CE6AB4796ABA3206A" )
                          , ((448, 511), "11F69B4D034B1D7213B9560FAE89FF2A"
                                      ++ "53D9D0C9EAFCAA7F27E9D119DEEEA299"
                                      ++ "AC8EC0EA0529846DAF90CF1D9BFBE406"
                                      ++ "043FE03F1713F249084BDD32FD98CD72" )
                          ]
    , testVector128 "Set 1, vector# 63"  "00000000000000010000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "FE4DF972E982735FFAEC4D66F929403F"
                                      ++ "7246FB5B2794118493DF068CD310DEB6"
                                      ++ "3EEEF12344E221A2D163CC666F5685B5"
                                      ++ "02F4883142FA867B0BA46BF17D011984" )
                          , ((192, 255), "4694F79AB2F3877BD590BA09B413F1BD"
                                      ++ "F394C4D8F2C20F551AA5A07207433204"
                                      ++ "C2BC3A3BA014886A08F4EC5E4D91CDD0"
                                      ++ "1D7A039C5B815754198B2DBCE68D25EA" )
                          , ((256, 319), "D1340204FB4544EFD5DAF28EDCC6FF03"
                                      ++ "B39FBEE708CAEF6ABD3E2E3AB5738B32"
                                      ++ "04EF38CACCC40B9FBD1E6F0206A2B564"
                                      ++ "E2F9EA05E10B6DD061F6AB94374681C0" )
                          , ((448, 511), "BB802FB53E11AFDC3104044D70448079"
                                      ++ "41FDAEF1042E0D35972D80CE77B4D560"
                                      ++ "083EB4113CDBC4AC56014D7FF94291DC"
                                      ++ "9387CEF74A0E165042BC12373C6E020C" )
                          ]
    , testVector128 "Set 1, vector# 72"  "00000000000000000080000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "8F8121BDD7B286465F03D64CA45A4A15"
                                      ++ "4BDF44560419A40E0B482CED194C4B32"
                                      ++ "4F2E9295C452B73B292BA7F55A692DEE"
                                      ++ "A5129A49167BA7AABBEED26E39B25E7A" )
                          , ((192, 255), "7E4388EDBBA6EC5882E9CBF01CFA6786"
                                      ++ "0F10F0A5109FCA7E865C3814EB007CC8"
                                      ++ "9585C2653BDCE30F667CF95A2AA425D3"
                                      ++ "5A531F558180EF3E32A9543AE50E8FD6" )
                          , ((256, 319), "527FF72879B1B809C027DFB7B39D02B3"
                                      ++ "04D648CD8D70F4E0465615B334ED9E2D"
                                      ++ "59703745467F1168A8033BA861841DC0"
                                      ++ "0E7E1AB5E96469F6DA01B8973D0D414A" )
                          , ((448, 511), "82653E0949A5D8E32C4D0A81BBF96F6A"
                                      ++ "7249D4D1E0DCDCC72B90565D9AF4D0AC"
                                      ++ "461C1EAC85E254DD5E567A009EEB3897"
                                      ++ "9A2FD1E4F32FAD15D177D766932190E1" )
                          ]
    , testVector128 "Set 1, vector# 81"  "00000000000000000000400000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "52FA8BD042682CD5AA21188EBF3B9E4A"
                                      ++ "EE3BE38AE052C5B37730E52C6CEE33C9"
                                      ++ "1B492F95A67F2F6C15425A8623C0C2AE"
                                      ++ "7275FFD0FCF13A0A293A784289BEACB4" )
                          , ((192, 255), "5F43C508BA6F728D032841618F96B103"
                                      ++ "19B094027E7719C28A8A8637D4B0C4D2"
                                      ++ "25D602EA23B40D1541A3F8487F25B14A"
                                      ++ "8CBD8D2001AC28EADFDC0325BA2C140E" )
                          , ((256, 319), "5C802C813FF09CAF632CA8832479F891"
                                      ++ "FB1016F2F44EFA81B3C872E37468B818"
                                      ++ "3EB32D8BD8917A858AEF47524FCC05D3"
                                      ++ "688C551FC8A42C8D9F0509018706E40E" )
                          , ((448, 511), "4CDD40DC6E9C0E4F84810ABE712003F6"
                                      ++ "4B23C6D0C88E61D1F303C3BBD89B58AA"
                                      ++ "098B44B5CD82EDCFC618D324A41317AC"
                                      ++ "6FED20C9A0C54A9ED1F4DA3BF2EC3C66" )
                          ]
    , testVector128 "Set 1, vector# 90"  "00000000000000000000002000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "6262315C736E88717E9627EECF4F6B55"
                                      ++ "BD10D5960A9961D572EFC7CBDB9A1F01"
                                      ++ "1733D3E17E4735BEFA16FE6B148F8661"
                                      ++ "4C1E37065A48ACF287FFE65C9DC44A58" )
                          , ((192, 255), "B43439584FB2FAF3B2937838D8000AC4"
                                      ++ "CD4BC4E582212A7741A0192F71C1F11B"
                                      ++ "58D7F779CA0E6E4B8BD58E00B50C3C53"
                                      ++ "DAF843467064A2DBE2FAD6FF6F40ECD8" )
                          , ((256, 319), "EE51EE875F6F1B8AF0334F509DF5692B"
                                      ++ "9B43CC63A586C2380AF3AE490DCD6CFF"
                                      ++ "7907BC3724AE3BBEAD79D436E6DADDB2"
                                      ++ "2141B3BA46C9BEC0E01B9D4F7657B387" )
                          , ((448, 511), "E5A4FE4A2FCA9A9ED779A9574283DC21"
                                      ++ "C85216D54486D9B182300D0593B1E2B0"
                                      ++ "10814F7066AEB955C057609CE9AF0D63"
                                      ++ "F057E17B19F57FFB7287EB2067C43B8D" )
                          ]
    , testVector128 "Set 1, vector# 99"  "00000000000000000000000010000000"
                                         "0000000000000000"
                          [ ((0, 63),    "82FD629BD82C3BE22910951E2E41F8FE"
                                      ++ "187E2BD198F6113AFF44B9B0689AA520"
                                      ++ "C8CCE4E8D3FBA69EDE748BCF18397214"
                                      ++ "F98D7ACF4424866A8670E98EBAB715A3" )
                          , ((192, 255), "342D80E30E2FE7A00B02FC62F7090CDD"
                                      ++ "ECBDFD283D42A00423113196A87BEFD8"
                                      ++ "B9E8AAF61C93F73CC6CBE9CC5AEC182F"
                                      ++ "3948B7857F96B017F3477A2EEC3AEB3B" )
                          , ((256, 319), "8233712B6D3CCB572474BE200D67E540"
                                      ++ "3FC62128D74CE5F790202C696BFFB7EE"
                                      ++ "3CAD255324F87291273A7719278FA313"
                                      ++ "1ABA12342692A2C0C58D27BA3725761B" )
                          , ((448, 511), "782600E7357AC69EA158C725B3E1E940"
                                      ++ "51A0CB63D0D1B4B3DF5F5037E3E1DE45"
                                      ++ "850578E9D513B90B8E5882D4DCA9F42B"
                                      ++ "E32621F4DCC1C77B38F1B0AC1227C196" )
                          ]
    , testVector128 "Set 1, vector#108"  "00000000000000000000000000080000"
                                         "0000000000000000"
                          [ ((0, 63),    "D244F87EB315A7EEF02CA314B440777E"
                                      ++ "C6C44660020B43189693500F3279FA01"
                                      ++ "7257BE0AB087B81F85FD55AAC5845189"
                                      ++ "C66E259B5412C4BDFD0EBE805FC70C8A" )
                          , ((192, 255), "5A2D8D3E431FB40E60856F05C7976206"
                                      ++ "42B35DAB0255764D986740699040702F"
                                      ++ "6CDE058458E842CB6E1843EBD336D374"
                                      ++ "23833EC01DFFF9086FEECAB8A165D29F" )
                          , ((256, 319), "443CEF4570C83517ED55C2F57058BB70"
                                      ++ "294CC8D7342597E2CD850F6C02E355CA"
                                      ++ "EB43C0A41F4BB74FFE9F6B0D25799140"
                                      ++ "D03792D667601AD7954D21BD7C174C43" )
                          , ((448, 511), "959C8B16A0ADEC58B544BE33CCF03277"
                                      ++ "E48C7916E333F549CDE16E2B4B6DCE2D"
                                      ++ "8D76C50718C0E77BFBEB3A3CB3CA14BF"
                                      ++ "40F65EBFAE1A5001EAB36E531414E87F" )
                          ]
    , testVector128 "Set 1, vector#117"  "00000000000000000000000000000400"
                                         "0000000000000000"
                          [ ((0, 63),    "44A74D35E73A7E7C37B009AE712783AC"
                                      ++ "86ACE0C02CB175656AF79023D91C909E"
                                      ++ "D2CB2F5C94BF8593DDC5E054D7EB726E"
                                      ++ "0E867572AF954F88E05A4DAFD00CCF0A" )
                          , ((192, 255), "FEC113A0255391D48A37CDF607AE1226"
                                      ++ "86305DDAD4CF1294598F2336AB6A5A02"
                                      ++ "9D927393454C2E014868137688C0417A"
                                      ++ "2D31D0FE9540D7246FE2F84D6052DE40" )
                          , ((256, 319), "79C2F7431D69E54C0474D8160113F364"
                                      ++ "8156A8963817C34AC9A9AD222543666E"
                                      ++ "7EAF03AF4EE03271C3ECED262E7B4C66"
                                      ++ "B0F618BAF3395423274DD1F73E2675E3" )
                          , ((448, 511), "75C1295C871B1100F27DAF19E5D5BF8D"
                                      ++ "880B9A54CEFDF1561B4351A32898F3C2"
                                      ++ "6A04AB1149C24FBFA2AC963388E64C43"
                                      ++ "65D716BCE8330BC03FA178DBE5C1E6B0" )
                          ]
    , testVector128 "Set 1, vector#126"  "00000000000000000000000000000002"
                                         "0000000000000000"
                          [ ((0, 63),    "E23A3638C836B1ACF7E27296E1F5A241"
                                      ++ "3C4CC351EFEF65E3672E7C2FCD1FA105"
                                      ++ "2D2C26778DB774B8FBA29ABED72D058E"
                                      ++ "E35EBA376BA5BC3D84F8E44ABD5DC2CC" )
                          , ((192, 255), "2A8BEB3C372A6570F54EB429FA7F562D"
                                      ++ "6EF14DF725861EDCE8132620EAA00D8B"
                                      ++ "1DFEF653B64E9C328930904A0EEB0132"
                                      ++ "B277BB3D9888431E1F28CDB0238DE685" )
                          , ((256, 319), "CCBEB5CA57104B95BF7BA5B12C8B8553"
                                      ++ "4CE9548F628CF53EF02C337D788BCE71"
                                      ++ "D2D3D9C355E7D5EB75C56D079CB7D99D"
                                      ++ "6AF0C8A86024B3AF5C2FC8A028413D93" )
                          , ((448, 511), "D00A5FDCE01A334C37E75634A8037B49"
                                      ++ "BEC06ACBD2243320E2CA41FB5619E6D8"
                                      ++ "75AB2007310D4149379C91EF4E199805"
                                      ++ "BE261E5C744F0DF21737E01243B7116F" )
                          ]
    , testVector128 "Set 2, vector#  0"  "00000000000000000000000000000000"
                                         "0000000000000000"
                          [ ((0, 63),    "6513ADAECFEB124C1CBE6BDAEF690B4F"
                                      ++ "FB00B0FCACE33CE806792BB414801998"
                                      ++ "34BFB1CFDD095802C6E95E251002989A"
                                      ++ "C22AE588D32AE79320D9BD7732E00338" )
                          , ((192, 255), "75E9D0493CA05D2820408719AFC75120"
                                      ++ "692040118F76B8328AC279530D846670"
                                      ++ "65E735C52ADD4BCFE07C9D93C0091790"
                                      ++ "2B187D46A25924767F91A6B29C961859" )
                          , ((256, 319), "0E47D68F845B3D31E8B47F3BEA660E2E"
                                      ++ "CA484C82F5E3AE00484D87410A1772D0"
                                      ++ "FA3B88F8024C170B21E50E0989E94A26"
                                      ++ "69C91973B3AE5781D305D8122791DA4C" )
                          , ((448, 511), "CCBA51D3DB400E7EB780C0CCBD3D2B5B"
                                      ++ "B9AAD82A75A1F746824EE5B9DAF7B794"
                                      ++ "7A4B808DF48CE94830F6C9146860611D"
                                      ++ "A649E735ED5ED6E3E3DFF7C218879D63" )
                          ]
    , testVector128 "Set 2, vector#  9"  "09090909090909090909090909090909"
                                         "0000000000000000"
                          [ ((0, 63),    "169060CCB42BEA7BEE4D8012A02F3635"
                                      ++ "EB7BCA12859FA159CD559094B3507DB8"
                                      ++ "01735D1A1300102A9C9415546829CBD2"
                                      ++ "021BA217B39B81D89C55B13D0C603359" )
                          , ((192, 255), "23EF24BB24195B9FD574823CD8A40C29"
                                      ++ "D86BD35C191E2038779FF696C712B6D8"
                                      ++ "2E7014DBE1AC5D527AF076C088C4A8D4"
                                      ++ "4317958189F6EF54933A7E0816B5B916" )
                          , ((256, 319), "D8F12ED8AFE9422B85E5CC9B8ADEC9D6"
                                      ++ "CFABE8DBC1082BCCC02F5A7266AA074C"
                                      ++ "A284E583A35837798CC0E69D4CE93765"
                                      ++ "3B8CDD65CE414B89138615CCB165AD19" )
                          , ((448, 511), "F70A0FF4ECD155E0F033604693A51E23"
                                      ++ "63880E2ECF98699E7174AF7C2C6B0FC6"
                                      ++ "59AE329599A3949272A37B9B2183A091"
                                      ++ "0922A3F325AE124DCBDD735364055CEB" )
                          ]
    , testVector128 "Set 2, vector# 18"  "12121212121212121212121212121212"
                                         "0000000000000000"
                          [ ((0, 63),    "05835754A1333770BBA8262F8A84D0FD"
                                      ++ "70ABF58CDB83A54172B0C07B6CCA5641"
                                      ++ "060E3097D2B19F82E918CB697D0F347D"
                                      ++ "C7DAE05C14355D09B61B47298FE89AEB" )
                          , ((192, 255), "5525C22F425949A5E51A4EAFA18F62C6"
                                      ++ "E01A27EF78D79B073AEBEC436EC8183B"
                                      ++ "C683CD3205CF80B795181DAFF3DC9848"
                                      ++ "6644C6310F09D865A7A75EE6D5105F92" )
                          , ((256, 319), "2EE7A4F9C576EADE7EE325334212196C"
                                      ++ "B7A61D6FA693238E6E2C8B53B900FF1A"
                                      ++ "133A6E53F58AC89D6A695594CE03F775"
                                      ++ "8DF9ABE981F23373B3680C7A4AD82680" )
                          , ((448, 511), "CB7A0595F3A1B755E9070E8D3BACCF95"
                                      ++ "74F881E4B9D91558E19317C4C254988F"
                                      ++ "42184584E5538C63D964F8EF61D86B09"
                                      ++ "D983998979BA3F44BAF527128D3E5393" )
                          ]
    , testVector128 "Set 2, vector# 27"  "1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B"
                                         "0000000000000000"
                          [ ((0, 63),    "72A8D26F2DF3B6713C2A053B3354DBA6"
                                      ++ "C10743C7A8F19261CF0E7957905748DD"
                                      ++ "D6D3333E2CBC6611B68C458D5CDBA2A2"
                                      ++ "30AC5AB03D59E71FE9C993E7B8E7E09F" )
                          , ((192, 255), "7B6132DC5E2990B0049A5F7F357C9D99"
                                      ++ "7733948018AE1D4F9DB999F4605FD78C"
                                      ++ "B548D75AC4657D93A20AA451B8F35E0A"
                                      ++ "3CD08880CCED7D4A508BA7FB49737C17" )
                          , ((256, 319), "EF7A7448D019C76ED0B9C18B5B2867CF"
                                      ++ "9AD84B789FB037E6B107B0A4615737B5"
                                      ++ "C1C113F91462CDA0BCB9ADDC09E8EA6B"
                                      ++ "99E4835FED25F5CC423EEFF56D851838" )
                          , ((448, 511), "6B75BDD0EC8D581CB7567426F0B92C9B"
                                      ++ "B5057A89C3F604583DB700A46D6B8DE4"
                                      ++ "1AF315AE99BB5C1B52C76272D1E262F9"
                                      ++ "FC7022CE70B435C27AE443284F5F84C1" )
                          ]
    , testVector128 "Set 2, vector# 36"  "24242424242424242424242424242424"
                                         "0000000000000000"
                          [ ((0, 63),    "76240D13C7E59CBD4183D162834A5D36"
                                      ++ "37CD09EE4F5AFE9C28CFA9466A4089F6"
                                      ++ "5C80C224A87F956459B173D720274D09"
                                      ++ "C573FCD128498D810460FDA1BB50F934" )
                          , ((192, 255), "71AF115217F3B7F77A05B56E32AD0889"
                                      ++ "BFA470B6DDC256D852C63B45688D7BC8"
                                      ++ "DC610D347A2600D7769C67B28D1FA25F"
                                      ++ "1AACFB8F9BB68BFE17357335D8FAC993" )
                          , ((256, 319), "6573CC1ADC0DE744F6694E5FBB59E5BF"
                                      ++ "5939CE5D13793E2F683C7F2C7DD9A460"
                                      ++ "575746688A0F17D419FE3E5F88654559"
                                      ++ "7B6705E1390542B4F953D568025F5BB3" )
                          , ((448, 511), "809179FAD4AD9B5C355A09E99C8BE931"
                                      ++ "4B9DF269F162C1317206EB3580CAE58A"
                                      ++ "B93A408C23739EF9538730FE687C8DAC"
                                      ++ "1CE95290BA4ACBC886153E63A613857B" )
                          ]
    , testVector128 "Set 2, vector# 45"  "2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D"
                                         "0000000000000000"
                          [ ((0, 63),    "3117FD618A1E7821EA08CDED410C8A67"
                                      ++ "BDD8F7BE3FCA9649BD3E297FD83A80AD"
                                      ++ "814C8904C9D7A2DC0DCAA641CFFF502D"
                                      ++ "78AFF1832D34C263C1938C1ADF01238F" )
                          , ((192, 255), "1E8CB540F19EC7AFCB366A25F74C0004"
                                      ++ "B682E06129030617527BECD16E3E3E00"
                                      ++ "27D818F035EDCDF56D8D4752AEF28BDB"
                                      ++ "FA0D3B008235173475F5FA105B91BEED" )
                          , ((256, 319), "637C3B4566BBEBBE703E4BF1C978CCD2"
                                      ++ "77AE3B8768DB97DF01983CDF3529B3EC"
                                      ++ "6B1137CA6F231047C13EA38649D0058E"
                                      ++ "BE5EF7B7BBA140F22338E382F1D6AB3F" )
                          , ((448, 511), "D407259B6355C343D64A5130DA55C057"
                                      ++ "E4AF722B70AC8A074262233677A457AF"
                                      ++ "EAA34E7FD6F15959A4C781C4C978F7B3"
                                      ++ "BC571BF66674F015A1EA5DB262E25BDC" )
                          ]
    , testVector128 "Set 2, vector# 54"  "36363636363636363636363636363636"
                                         "0000000000000000"
                          [ ((0, 63),    "7FED83B9283449AD8EBFC935F5F36407"
                                      ++ "5C9008ADE8626D350770E2DBD058F053"
                                      ++ "F7E5300B088B1341EC54C2BEE72A520C"
                                      ++ "35C673E79CC4ED0A6D8F4C15FBDD090B" )
                          , ((192, 255), "D780206A2537106610D1C95BF7E9121B"
                                      ++ "EDE1F0B8DFBE83CBC49C2C653DD187F7"
                                      ++ "D84A2F4607BF99A96B3B84FB792340D4"
                                      ++ "E67202FB74EC24F38955F345F21CF3DB" )
                          , ((256, 319), "6CA21C5DC289674C13CFD4FCBDEA8356"
                                      ++ "0A90F53BB54F16DBF274F5CC56D7857C"
                                      ++ "D3E3B06C81C70C828DC30DADEBD92F38"
                                      ++ "BB8C24136F37797A647584BCEE68DF91" )
                          , ((448, 511), "471936CE9C84E131C4C5792B769654B8"
                                      ++ "9644BFAFB1149130E580FD805A325B62"
                                      ++ "8CDE5FAE0F5C7CFFEF0D931F8F517A92"
                                      ++ "9E892D3789B74217A81BAEFE441E47ED" )
                          ]
    , testVector128 "Set 2, vector# 63"  "3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F"
                                         "0000000000000000"
                          [ ((0, 63),    "C224F33B124D6692263733DFD5BF5271"
                                      ++ "7D1FB45EC1CEDCA6BF92BA44C1EADA85"
                                      ++ "F7B031BCC581A890FD275085C7AD1C3D"
                                      ++ "652BCA5F4D7597DECDB2232318EABC32" )
                          , ((192, 255), "090325F54C0350AD446C19ABDCAEFF52"
                                      ++ "EC57F5A13FB55FEDE4606CEC44EC658B"
                                      ++ "BB13163481D2C84BF9409313F6470A0D"
                                      ++ "A9803936094CC29A8DE7613CBFA77DD5" )
                          , ((256, 319), "1F66F5B70B9D12BC7092C1846498A2A0"
                                      ++ "730AA8FA8DD97A757BBB878320CE6633"
                                      ++ "E5BCC3A5090F3F75BE6E72DD1E8D95B0"
                                      ++ "DE7DBFDD764E484E1FB854B68A7111C6" )
                          , ((448, 511), "F8AE560041414BE888C7B5EB3082CC7C"
                                      ++ "4DFBBA5FD103F522FBD95A7166B91DE6"
                                      ++ "C78FB47413576EC83F0EDE6338C9EDDB"
                                      ++ "81757B58C45CBD3A3E29E491DB1F04E2" )
                          ]
    , testVector128 "Set 2, vector# 72"  "48484848484848484848484848484848"
                                         "0000000000000000"
                          [ ((0, 63),    "11BF31E22D7458C189092A1DE3A4905B"
                                      ++ "A2FA36858907E3511FB63FDFF2C5C2A1"
                                      ++ "5B651B2C2F1A3A43A718642152806967"
                                      ++ "2B6BB0AEC10452F1DAA9FC73FF5A396A" )
                          , ((192, 255), "D1E1619E4BD327D2A124FC52BC15B194"
                                      ++ "0B05394ECE5926E1E1ADE7D3FC8C6E91"
                                      ++ "E43889F6F9C1FD5C094F6CA25025AE4C"
                                      ++ "CC4FDC1824936373DBEE16D62B81112D" )
                          , ((256, 319), "F900E9B0665F84C939D5FE4946FA7B41"
                                      ++ "E34F06058522A2DB49E210E3E5385E58"
                                      ++ "97C24F6350C6CCA578285325CC16F558"
                                      ++ "6DC662FFBEA41BAC68996BAAB9F32D1F" )
                          , ((448, 511), "40587ECAD15841F1BD1D236A61051574"
                                      ++ "A974E15292F777ABDED64D2B761892BE"
                                      ++ "F3DD69E479DE0D02CC73AF76E81E8A77"
                                      ++ "F3CEE74180CB5685ACD4F0039DFFC3B0" )
                          ]
    , testVector128 "Set 2, vector# 81"  "51515151515151515151515151515151"
                                         "0000000000000000"
                          [ ((0, 63),    "EBC464423EADEF13E845C595A9795A58"
                                      ++ "5064F478A1C8582F07A4BA68E81329CB"
                                      ++ "26A13C2EA0EFE9094B0A749FDB1CC6F9"
                                      ++ "C2D293F0B395E14EB63075A39A2EDB4C" )
                          , ((192, 255), "F4BBBBCE9C5869DE6BAF5FD4AE835DBE"
                                      ++ "5B7F1752B2972086F3383E9D180C2FE5"
                                      ++ "5618846B10EB68AC0EB0865E0B167C6D"
                                      ++ "3A843B29336BC1100A4AB7E8A3369959" )
                          , ((256, 319), "3CEB39E3D740771BD49002EA8CD99851"
                                      ++ "8A8C70772679ECAF2030583AED43F77F"
                                      ++ "565FECDBEF333265A2E1CC42CB606980"
                                      ++ "AEF3B24C436A12C85CBDC5EBD97A9177" )
                          , ((448, 511), "EF651A98A98C4C2B61EA8E7A673F5D4F"
                                      ++ "D832D1F9FD19EE4537B6FEC7D11C6B2F"
                                      ++ "3EF5D764EEAD396A7A2E32662647BFC0"
                                      ++ "7F02A557BA6EF046C8DE3781D74332B0" )
                          ]
    , testVector128 "Set 2, vector# 90"  "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A"
                                         "0000000000000000"
                          [ ((0, 63),    "F40253BAA835152E1582646FD5BD3FED"
                                      ++ "638EB3498C80BFB941644A7750BBA565"
                                      ++ "3130CC97A937A2B27AFBB3E679BC42BE"
                                      ++ "87F83723DC6F0D61DCE9DE8608AC62AA" )
                          , ((192, 255), "A5A1CD35A230ED57ADB8FE16CD2D2EA6"
                                      ++ "055C32D3E621A0FD6EB6717AA916D478"
                                      ++ "57CD987C16E6112EDE60CCB0F7014642"
                                      ++ "2788017A6812202362691FDA257E5856" )
                          , ((256, 319), "81F0D04A929DB4676F6A3E6C15049779"
                                      ++ "C4EC9A12ACF80168D7E9AA1D6FA9C13E"
                                      ++ "F2956CEE750A89103B48F22C06439C5C"
                                      ++ "E9129996455FAE2D7775A1D8D39B00CE" )
                          , ((448, 511), "3F6D60A0951F0747B94E4DDE3CA4ED4C"
                                      ++ "96694B7534CD9ED97B96FAAD3CF00D4A"
                                      ++ "EF12919D410CD9777CD5F2F3F2BF160E"
                                      ++ "BBA3561CC24345D9A09978C3253F6DCB" )
                          ]
    , testVector128 "Set 2, vector# 99"  "63636363636363636363636363636363"
                                         "0000000000000000"
                          [ ((0, 63),    "ED5FF13649F7D8EDFC783EFDF2F843B3"
                                      ++ "68776B19390AF110BEF12EAC8EC58A2E"
                                      ++ "8CDAB6EC9049FBDA23A615C536C3A313"
                                      ++ "799E21668C248EC864D5D5D99DED80B3" )
                          , ((192, 255), "845ACE9B870CF9D77597201988552DE5"
                                      ++ "3FD40D2C8AC51ABE1335F6A2D0035DF8"
                                      ++ "B10CACAD851E000BAC6EA8831B2FBCFE"
                                      ++ "B7C94787E41CC541BAC3D9D26DB4F19D" )
                          , ((256, 319), "981580764B81A4E12CA1F36634B59136"
                                      ++ "5E4BDB6C12DE13F2F337E72E018029C5"
                                      ++ "A0BECDA7B6723DD609D81A314CE39619"
                                      ++ "0E82848893E5A44478B08340F90A73F3" )
                          , ((448, 511), "4CD3B072D5720E6C64C9476552D1CFF4"
                                      ++ "D4EF68DCBD11E8D516F0C248F9250B57"
                                      ++ "1990DD3AFC0AE8452896CCCC0BD0EFDF"
                                      ++ "17B616691AB3DF9AF6A42EDCA54BF9CD" )
                          ]
    , testVector128 "Set 2, vector#108"  "6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C"
                                         "0000000000000000"
                          [ ((0, 63),    "78ED06021C5C7867D176DA2A96C4BBAA"
                                      ++ "494F451F21875446393E9688205ED63D"
                                      ++ "EA8ADEB1A2381201F576C5A541BC8887"
                                      ++ "4078608CA8F2C2A6BDCDC1081DD254CC" )
                          , ((192, 255), "C1747F85DB1E4FB3E29621015314E3CB"
                                      ++ "261808FA6485E59057B60BE82851CFC9"
                                      ++ "48966763AF97CB9869567B763C745457"
                                      ++ "5022249DFE729BD5DEF41E6DBCC68128" )
                          , ((256, 319), "1EE4C7F63AF666D8EDB2564268ECD127"
                                      ++ "B4D015CB59487FEAF87D0941D42D0F8A"
                                      ++ "24BD353D4EF765FCCF07A3C3ACF71B90"
                                      ++ "E03E8AEA9C3F467FE2DD36CEC00E5271" )
                          , ((448, 511), "7AFF4F3A284CC39E5EAF07BA6341F065"
                                      ++ "671147CA0F073CEF2B992A7E21690C82"
                                      ++ "71639ED678D6A675EBDAD48336584213"
                                      ++ "15A2BA74754467CCCE128CCC62668D0D" )
                          ]
    , testVector128 "Set 2, vector#117"  "75757575757575757575757575757575"
                                         "0000000000000000"
                          [ ((0, 63),    "D935C93A8EBB90DB53A27BF9B41B3345"
                                      ++ "23E1DFDE3BFFC09EA97EFB9376D38C7D"
                                      ++ "6DC67AAB21EA3A5C07B6503F986F7E8D"
                                      ++ "9E11B3150BF0D38F36C284ADB31FACF8" )
                          , ((192, 255), "DA88C48115010D3CD5DC0640DED2E652"
                                      ++ "0399AAFED73E573CBAF552C6FE06B1B3"
                                      ++ "F3ADE3ADC19DA311B675A6D83FD48E38"
                                      ++ "46825BD36EB88001AE1BD69439A0141C" )
                          , ((256, 319), "14EA210224DAF4FC5D647C78B6BFEF7D"
                                      ++ "724DC56DCDF832B496DEAD31DD948DB1"
                                      ++ "944E17AB2966973FD7CCB1BC9EC0335F"
                                      ++ "35326D5834EE3B08833358C4C28F70DE" )
                          , ((448, 511), "D5346E161C083E00E247414F44E0E737"
                                      ++ "5B435F426B58D482A37694331D7C5DC9"
                                      ++ "7D8953E6A852625282973ECCFD012D66"
                                      ++ "4C0AFA5D481A59D7688FDB54C55CD04F" )
                          ]
    , testVector128 "Set 2, vector#126"  "7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E"
                                         "0000000000000000"
                          [ ((0, 63),    "45A43A587C45607441CE3AE200467977"
                                      ++ "88879C5B77FDB90B76F7D2DF27EE8D94"
                                      ++ "28A5B5AF35E2AAE242E6577BEC92DA09"
                                      ++ "29A6AFB3CB8F8496375C98085460AB95" )
                          , ((192, 255), "14AE0BA973AE19E6FD674413C276AB9D"
                                      ++ "99AA0048822AFB6F0B68A2741FB5CE2F"
                                      ++ "64F3D862106EF2BDE19B39209F75B92B"
                                      ++ "DBE9015D63FDFD7B9E8A776291F4E831" )
                          , ((256, 319), "C26FA1812FFC32EFF2954592A0E1E5B1"
                                      ++ "26D5A2196624156E3DFD0481205B24D5"
                                      ++ "613B0A75AF3CBC8BBE5911BE93125BD3"
                                      ++ "D3C50C92910DBA05D80666632E5DF9EF" )
                          , ((448, 511), "AD0DABE5AF74AB4F62B4699E0D667BBF"
                                      ++ "01B4DCF0A45514554CAC4DFDE453EFF1"
                                      ++ "E51BE5B74B37512C40E3608FB0E65A3F"
                                      ++ "D4EAFA27A3BB0D6E1300C594CB0D1254" )
                          ]
    , testVector128 "Set 2, vector#135"  "87878787878787878787878787878787"
                                         "0000000000000000"
                          [ ((0, 63),    "09E15E82DFA9D821B8F68789978D0940"
                                      ++ "48892C624167BA88AD767CAEFDE80E25"
                                      ++ "F57467156B8054C8E88F3478A2897A20"
                                      ++ "344C4B05665E7438AD1836BE86A07B83" )
                          , ((192, 255), "2D752E53C3FCA8D3CC4E760595D588A6"
                                      ++ "B321F910B8F96459DBD42C6635063246"
                                      ++ "60A527C66A53B406709262B0E42F11CB"
                                      ++ "0AD2450A1FB2F48EA85C1B39D4408DB9" )
                          , ((256, 319), "1EC94A21BD2C0408D3E15104FA25D15D"
                                      ++ "6E3E0D3F8070D84184D35B6302BF62AE"
                                      ++ "A282E3640820CC09E1528B684B740018"
                                      ++ "0598D6960EC92E4EC4C9E533E1BA06F1" )
                          , ((448, 511), "D0AC302C5CC256351E24CFFD11F0BD8A"
                                      ++ "0BE1277EDDCB3EE4D530E051712A710D"
                                      ++ "F4513FD6438B7A355CCF4FEDA9A60F2A"
                                      ++ "C375508F998C642E6C51724FE9462F7F" )
                          ]
    , testVector128 "Set 2, vector#144"  "90909090909090909090909090909090"
                                         "0000000000000000"
                          [ ((0, 63),    "EA869D49E7C75E07B551C24EBE351B4E"
                                      ++ "7FD9CB26413E55A8A977B766650F81EF"
                                      ++ "CA06E30107F76DC97EA9147FFA7CA66A"
                                      ++ "FD4D4DA538CDA1C27E8D948CC406FB89" )
                          , ((192, 255), "436A8EC10421116CD03BF95A4DAAE630"
                                      ++ "1BB8C724B3D481099C70B26109971CCE"
                                      ++ "ACBCE35C8EE98BBB0CD553B5C4181125"
                                      ++ "00262C7EA10FAAC8BA9A30A04222D8E2" )
                          , ((256, 319), "47487A34DE325E79838475B1757D5D29"
                                      ++ "3C931F9E57579FCA5E04A40E4A0A38CF"
                                      ++ "D1614F9CEF75F024FFF5D972BD671DC9"
                                      ++ "FB2A80F64E8A2D82C3BAA5DDFD1E6821" )
                          , ((448, 511), "3FDCAD4E7B069391FAB74C836D58DE23"
                                      ++ "95B27FFAE47D633912AE97E7E3E60264"
                                      ++ "CA0DC540D33122320311C5CFC9E26D63"
                                      ++ "2753AC45B6A8E81AC816F5CA3BBDB1D6" )
                          ]
    , testVector128 "Set 2, vector#153"  "99999999999999999999999999999999"
                                         "0000000000000000"
                          [ ((0, 63),    "7B3AA4599561C9059739C7D18D342CF2"
                                      ++ "E73B3B9E1E85D38EDB41AEFADD81BF24"
                                      ++ "1580885078CA10D338598D18B3E4B693"
                                      ++ "155D12D362D533494BA48142AB068F68" )
                          , ((192, 255), "D27864FC30D5FD278A9FB83FADADFD2F"
                                      ++ "E72CE78A2563C031791D55FF31CF5946"
                                      ++ "4BE7422C81968A70E040164603DC0B0A"
                                      ++ "EEE93AC497CC0B770779CE6058BE80CF" )
                          , ((256, 319), "4C5A87029660B65782FD616F48CFD600"
                                      ++ "6DFB158682DC80E085E52163BE2947E2"
                                      ++ "70A0FD74DC8DC2F5920E59F28E225280"
                                      ++ "FAC96BA78B8007E3D0DF6EF7BF835993" )
                          , ((448, 511), "F5A2ECD04452358970E4F8914FC08E82"
                                      ++ "926ECFF33D9FC0977F10241E7A50E528"
                                      ++ "996A7FB71F79FC30BF881AF6BA19016D"
                                      ++ "DC077ED22C58DC57E2BDBDA1020B30B2" )
                          ]
    , testVector128 "Set 2, vector#162"  "A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2"
                                         "0000000000000000"
                          [ ((0, 63),    "9776A232A31A22E2F10D203A2A1B60B9"
                                      ++ "D28D64D6D0BF32C8CCA1BBF6B57B1482"
                                      ++ "BCC9FCF7BBE0F8B61C4BF64C540474BC"
                                      ++ "F1F9C1C808CCBE6693668632A4E8653B" )
                          , ((192, 255), "5C746D64A3195079079028D74CE029A8"
                                      ++ "7F72B30B34B6C7459998847C42F2E44D"
                                      ++ "843CF196229EED471B6BBDBA63BE3B52"
                                      ++ "9B8AF4B5846EB0AB008261E161707B76" )
                          , ((256, 319), "F780FE5204AC188A680F41068A9F5018"
                                      ++ "2D9154D6D5F1886034C270A8C3AF61DF"
                                      ++ "945381B7ADCA546E153DBF0E6EA2DDDA"
                                      ++ "4EDA3E7F7CF4E2043C5E20AF659282B4" )
                          , ((448, 511), "71D24CD8B4A70554906A32A5EFDFA8B8"
                                      ++ "34C324E6F35240257A0A27485103616D"
                                      ++ "D41C8F4108D1FC76AB72AF166100AB17"
                                      ++ "212492A72099ACF6F9EB53AC50BD8B8B" )
                          ]
    , testVector128 "Set 2, vector#171"  "ABABABABABABABABABABABABABABABAB"
                                         "0000000000000000"
                          [ ((0, 63),    "62DF49A919AF1367D2AAF1EB608DE1FD"
                                      ++ "F8B93C2026389CEBE93FA389C6F28458"
                                      ++ "48EBBE70B3A3C8E79061D78E9ED24ED9"
                                      ++ "AA7BB6C1D726AA060AEFC4FFE70F0169" )
                          , ((192, 255), "E7A4DF0D61453F612FB558D1FAE198AA"
                                      ++ "B1979F91E1792C99423E0C5733459365"
                                      ++ "70915B60210F1F9CA8845120E6372659"
                                      ++ "B02A179A4D679E8EDDDDF8843ABAB7A4" )
                          , ((256, 319), "C9501A02DD6AFB536BD2045917B016B8"
                                      ++ "3C5150A7232E945A53B4A61F90C5D0FB"
                                      ++ "6E6AC45182CBF428772049B32C825D1C"
                                      ++ "33290DBEEC9EF3FE69F5EF4FAC95E9B1" )
                          , ((448, 511), "B8D487CDD057282A0DDF21CE3F421E2A"
                                      ++ "C9696CD36416FA900D12A20199FE0018"
                                      ++ "86C904AB629194AECCC28E59A54A1357"
                                      ++ "47B7537D4E017B66538E5B1E83F88367" )
                          ]
    , testVector128 "Set 2, vector#180"  "B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4"
                                         "0000000000000000"
                          [ ((0, 63),    "6F703F3FF0A49665AC70CD9675902EE7"
                                      ++ "8C60FF8BEB931011FC89B0F28D6E176A"
                                      ++ "9AD4D494693187CB5DB08FF727477AE6"
                                      ++ "4B2EF7383E76F19731B9E23186212720" )
                          , ((192, 255), "AD26886ABF6AD6E0CA4E305E468DA1B3"
                                      ++ "69F0ADD3E14364C8A95BD78C5F2762B7"
                                      ++ "2915264A022AD11B3C6D312B5F6526E0"
                                      ++ "183D581B57973AFB824945BFB78CEB8F" )
                          , ((256, 319), "FE29F08A5C157B87C600CE4458F274C9"
                                      ++ "86451983FE5AE561DF56139FF33755D7"
                                      ++ "1100286068A32559B169D8C2161E215D"
                                      ++ "BC32FAEA11B652284795C144CF3E693E" )
                          , ((448, 511), "7974578366C3E999028FA8318D82AAAA"
                                      ++ "8ED3FD4DFB111CBF0F529C251BA91DC6"
                                      ++ "ACFA9795C90C954CEA287D23AD979028"
                                      ++ "E974393B4C3ABA251BCB6CECCD09210E" )
                          ]
    , testVector128 "Set 2, vector#189"  "BDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBD"
                                         "0000000000000000"
                          [ ((0, 63),    "61900F2EF2BEA2F59971C82CDFB52F27"
                                      ++ "9D81B444833FF02DD0178A53A8BFB9E1"
                                      ++ "FF3B8D7EC799A7FBB60EADE8B1630C12"
                                      ++ "1059AA3E756702FEF9EEE7F233AFC79F" )
                          , ((192, 255), "D27E0784038D1B13833ACD396413FF10"
                                      ++ "D35F3C5C04A710FC58313EEBC1113B2C"
                                      ++ "FA20CBD1AEA4433C6650F16E7C3B6830"
                                      ++ "2E5F6B58D8E4F26D91F19FE981DEF939" )
                          , ((256, 319), "B658FB693E80CE50E3F64B910B660BEB"
                                      ++ "142B4C4B61466424A9884D22EB80B8B4"
                                      ++ "0C26BEA869118ED068DCC83F9E4C68F1"
                                      ++ "7A3597D0FE0E36700D01B4252EE0010E" )
                          , ((448, 511), "9FC658A20D3107A34680CC75EB3F76D6"
                                      ++ "A2150490E9F6A3428C9AD57F2A252385"
                                      ++ "C956B01C31C978E219BE351A534DB23B"
                                      ++ "99908DACC6726196742D0B7E1D88472C" )
                          ]
    , testVector128 "Set 2, vector#198"  "C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6"
                                         "0000000000000000"
                          [ ((0, 63),    "42D1C40F11588014006445E81C8219C4"
                                      ++ "370E55E06731E09514956834B2047EE2"
                                      ++ "8A9DAECC7EB25F34A311CC8EA28EDCD2"
                                      ++ "4A539160A0D8FDAA1A26E9F0CDFE0BE3" )
                          , ((192, 255), "976201744266DEABBA3BFE206295F40E"
                                      ++ "8D9D169475C11659ADA3F6F25F11CEF8"
                                      ++ "CD6B851B1F72CD3E7D6F0ABAF8FB929D"
                                      ++ "DB7CF0C7B128B4E4C2C977297B2C5FC9" )
                          , ((256, 319), "D3601C4CD44BBEEFD5DAD1BDFF12C190"
                                      ++ "A5F0B0CE95C019972863F4309CE566DE"
                                      ++ "62BECB0C5F43360A9A09EB5BAB87CF13"
                                      ++ "E7AB42D71D5E1229AF88667D95E8C96F" )
                          , ((448, 511), "69EAA4BAAAA795BCF3B96E79C931A1F2"
                                      ++ "D2DD16A242714358B106F38C1234A5BB"
                                      ++ "D269E68A03539EFAFA79455ADBE1B984"
                                      ++ "E9766B0720947E1365FDF076F73639CD" )
                          ]
    , testVector128 "Set 2, vector#207"  "CFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCF"
                                         "0000000000000000"
                          [ ((0, 63),    "9C09F353BF5ED33EDEF88D73985A14DB"
                                      ++ "C1390F08236461F08FDCAF9A7699FD7C"
                                      ++ "4C602BE458B3437CEB1464F451ED021A"
                                      ++ "0E1C906BA59C73A8BA745979AF213E35" )
                          , ((192, 255), "437E3C1DE32B0DB2F0A57E41A7282670"
                                      ++ "AC223D9FD958D111A8B45A70A1F863E2"
                                      ++ "989A97386758D44060F6BFFF5434C908"
                                      ++ "88B4BB4EDAE6528AAADC7B81B8C7BEA3" )
                          , ((256, 319), "94007100350C946B6D12B7C6A2FD1215"
                                      ++ "682C867257C12C74E343B79E3DE79A78"
                                      ++ "2D74663347D8E633D8BE9D288A2A64A8"
                                      ++ "55C71B4496587ADECCB4F30706BB4BD9" )
                          , ((448, 511), "585D0C2DB901F4004846ADBAA754BCA8"
                                      ++ "2B66A94C9AF06C914E3751243B87581A"
                                      ++ "FAE281312A492DBEE8D6BB64DD748F44"
                                      ++ "5EF88F82AB44CBA33D767678914BDE77" )
                          ]
    , testVector128 "Set 2, vector#216"  "D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8"
                                         "0000000000000000"
                          [ ((0, 63),    "4965F30797EE95156A0C141D2ACA5232"
                                      ++ "04DD7C0F89C6B3F5A2AC1C59B8CF0DA4"
                                      ++ "01B3906A6A3C94DA1F1E0046BD895052"
                                      ++ "CB9E95F667407B4EE9E579D7A2C91861" )
                          , ((192, 255), "8EDF23D6C8B062593C6F32360BF271B7"
                                      ++ "ACEC1A4F7B66BF964DFB6C0BD93217BB"
                                      ++ "C5FACC720B286E93D3E9B31FA8C4C762"
                                      ++ "DF1F8A3836A8FD8ACBA384B8093E0817" )
                          , ((256, 319), "44FA82E9E469170BA6E5E8833117DAE9"
                                      ++ "E65401105C5F9FEA0AF682E53A627B4A"
                                      ++ "4A621B63F7CE5265D3DFADFBFD4A2B6C"
                                      ++ "2B40D2249EB0385D959F9FE73B37D67D" )
                          , ((448, 511), "828BA57593BC4C2ACB0E8E4B8266C1CC"
                                      ++ "095CE9A761FB68FC57D7A2FCFF768EFB"
                                      ++ "39629D3378549FEE08CCF48A4A4DC2DD"
                                      ++ "17E72A1454B7FA82E2ACF90B4B8370A7" )
                          ]
    , testVector128 "Set 2, vector#225"  "E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1"
                                         "0000000000000000"
                          [ ((0, 63),    "5C7BA38DF4789D45C75FCC71EC9E5751"
                                      ++ "B3A60AD62367952C6A87C0657D6DB3E7"
                                      ++ "1053AC73E75FF4B66177B3325B1BBE69"
                                      ++ "AEE30AD5867D68B660603FE4F0BF8AA6" )
                          , ((192, 255), "B9C7460E3B6C313BA17F7AE115FC6A8A"
                                      ++ "499943C70BE40B8EF9842C8A934061E1"
                                      ++ "E9CB9B4ED3503165C528CA6E0CF2622B"
                                      ++ "B1F16D24657BDAEDB9BA8F9E193B65EB" )
                          , ((256, 319), "406CD92883E991057DFD80BC8201067F"
                                      ++ "35700264A4DFC28CF23EE32573DCB420"
                                      ++ "91FEF27548613999E5C5463E840FE957"
                                      ++ "60CF80CC5A05A74DE49E7724273C9EA6" )
                          , ((448, 511), "F13D615B49786D74B6591BA6887A7669"
                                      ++ "136F34B69D31412D4A9CB90234DAFCC4"
                                      ++ "1551743113701EF6191A577C7DB72E2C"
                                      ++ "B723C738317848F7CC917E1510F02791" )
                          ]
    , testVector128 "Set 2, vector#234"  "EAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEA"
                                         "0000000000000000"
                          [ ((0, 63),    "5B06F5B01529B8C57B73A410A61DD757"
                                      ++ "FE5810970AA0CBFAD3404F17E7C7B645"
                                      ++ "9DD7F615913A0EF2DCC91AFC57FA660D"
                                      ++ "6C7352B537C65CD090F1DE51C1036AB5" )
                          , ((192, 255), "0F613F9E9F03199DF0D0A5C5BE253CDF"
                                      ++ "138903876DE7F7B0F40B2F840F322F27"
                                      ++ "0C0618D05ABB1F013D8744B231555A8E"
                                      ++ "CB14A9E9C9AF39EDA91D36700F1C25B3" )
                          , ((256, 319), "4D9FAB87C56867A687A03BF3EDCC224A"
                                      ++ "C54D04450AB6F78A642715AF62CF5192"
                                      ++ "15E2CDF5338E45554B852B6FB552BCAF"
                                      ++ "5C599BDF9FA679962F038976CDA2DEFA" )
                          , ((448, 511), "E0F80A9BF168EB523FD9D48F19CA96A1"
                                      ++ "8F89C1CF11A3ED6EC8AEAB99082DE99B"
                                      ++ "E46DE2FB23BE4A305F185CF3A8EA377C"
                                      ++ "CA1EF46FD3192D03DCAE13B79960FEF4" )
                          ]
    , testVector128 "Set 2, vector#243"  "F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3"
                                         "0000000000000000"
                          [ ((0, 63),    "E7BC9C13F83F51E8855E83B81AF1FFB9"
                                      ++ "676300ABAB85986B0B44441DDEFAB83B"
                                      ++ "8569C4732D8D991696BD7B6694C6CB20"
                                      ++ "872A2D4542192BE81AA7FF8C1634FC61" )
                          , ((192, 255), "0B429A2957CBD422E94012B49C443CBC"
                                      ++ "2E13EFDE3B867C6018BABFDE9ED3B803"
                                      ++ "6A913C770D77C60DCD91F23E03B3A576"
                                      ++ "66847B1CACFCBCFF57D9F2A2BAD6131D" )
                          , ((256, 319), "EA2CBD32269BB804DD2D641452DC09F9"
                                      ++ "64CB2BCD714180E94609C1209A8C26D1"
                                      ++ "256067F1B86AA4F886BB3602CF96B4DD"
                                      ++ "7039F0326CD24D7C2D69DE22D9E24624" )
                          , ((448, 511), "CA0DD398EA7E543F1F680BF83E2B773B"
                                      ++ "BB5B0A931DEADDEC0884F7B823FC686E"
                                      ++ "71D7E4C033C65B03B292426CE4E1A7A8"
                                      ++ "A9D037303E6D1F0F45FDFB0FFE322F93" )
                          ]
    , testVector128 "Set 2, vector#252"  "FCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFC"
                                         "0000000000000000"
                          [ ((0, 63),    "C93DA97CB6851BCB95ABFAF547C20DF8"
                                      ++ "A54836178971F748CF6D49AEF3C9CE8C"
                                      ++ "E7D284571D871EFD51B6A897AF698CD8"
                                      ++ "F2B050B6EB21A1A58A9FC77200B1A032" )
                          , ((192, 255), "5B4144FD0C46CEE4348B598EEF76D16B"
                                      ++ "1A71CBF85F4D9926402133846136C59F"
                                      ++ "BE577B8B7EB8D6A67A48358573C06876"
                                      ++ "6AC76A308A14154E2FA9BD9DCA8842E6" )
                          , ((256, 319), "3BF67A79DF6FE3C32DA7A53CD0D37237"
                                      ++ "16A99BF7D168A25C93C29DF2945D9BCB"
                                      ++ "F78B669195411BD86D3F890A462734AB"
                                      ++ "10F488E9952334D7242E51AC6D886D60" )
                          , ((448, 511), "65629AA9654930681578EEC971A48D83"
                                      ++ "90FBF82469A385B8BCF28B2C1E9F13CE"
                                      ++ "FC06F54335B4D5DE011F3DCE2B94D38F"
                                      ++ "1A04871E273FCD2A8FA32C0E08710E69" )
                          ]
    , testVector128 "Set 3, vector#  0"  "000102030405060708090A0B0C0D0E0F"
                                         "0000000000000000"
                          [ ((0, 63),    "2DD5C3F7BA2B20F76802410C68868889"
                                      ++ "5AD8C1BD4EA6C9B140FB9B90E21049BF"
                                      ++ "583F527970EBC1A4C4C5AF117A5940D9"
                                      ++ "2B98895B1902F02BF6E9BEF8D6B4CCBE" )
                          , ((192, 255), "AB56CC2C5BFFEF174BBE28C48A17039E"
                                      ++ "CB795F4C2541E2F4AE5C69CA7FC2DED4"
                                      ++ "D39B2C7B936ACD5C2ECD4719FD6A3188"
                                      ++ "323A14490281CBE8DAC48E4664FF3D3B" )
                          , ((256, 319), "9A18E827C33633E932FC431D697F0775"
                                      ++ "B4C5B0AD26D1ACD5A643E3A01A065821"
                                      ++ "42A43F48E5D3D9A91858887310D39969"
                                      ++ "D65E7DB788AFE27D03CD985641967357" )
                          , ((448, 511), "752357191E8041ABB8B5761FAF9CB9D7"
                                      ++ "3072E10B4A3ED8C6ADA2B05CBBAC298F"
                                      ++ "2ED6448360F63A51E073DE02338DBAF2"
                                      ++ "A8384157329BC31A1036BBB4CBFEE660" )
                          ]
    , testVector128 "Set 3, vector#  9"  "090A0B0C0D0E0F101112131415161718"
                                         "0000000000000000"
                          [ ((0, 63),    "0F8DB5661F92FB1E7C760741430E15BB"
                                      ++ "36CD93850A901F88C40AB5D03C3C5FCE"
                                      ++ "71E8F16E239795862BEC37F63490335B"
                                      ++ "B13CD83F86225C8257AB682341C2D357" )
                          , ((192, 255), "002734084DF7F9D6613508E587A4DD42"
                                      ++ "1D317B45A6918B48E007F53BEB3685A9"
                                      ++ "235E5F2A7FACC41461B1C22DC55BF82B"
                                      ++ "54468C8523508167AAF83ABBFC39C67B" )
                          , ((256, 319), "3C9F43ED10724681186AC02ACFEC1A3A"
                                      ++ "090E6C9AC1D1BC92A5DBF407664EBCF4"
                                      ++ "563676257518554C90656AC1D4F167B8"
                                      ++ "B0D3839EB8C9E9B127665DCE0B1FD78C" )
                          , ((448, 511), "46B7C56E7ED713AAB757B24056AF58C6"
                                      ++ "AD3C86270CFEAE4AADB35F0DB2D96932"
                                      ++ "1A38388D00ED9C2AD3A3F6D8BE0DE7F7"
                                      ++ "ADA068F67525A0996DE5E4DF490DF700" )
                          ]
    , testVector128 "Set 3, vector# 18"  "12131415161718191A1B1C1D1E1F2021"
                                         "0000000000000000"
                          [ ((0, 63),    "4B135E9A5C9D54E6E019B5A2B48B9E6E"
                                      ++ "17F6E6667B9D43BC3F892AD6ED64C584"
                                      ++ "4FE52F75BD67F5C01523EE026A385108"
                                      ++ "3FBA5AC0B6080CE3E6A2F5A65808B0AC" )
                          , ((192, 255), "E45A7A605BCFBBE77E781BBE78C270C5"
                                      ++ "AC7DAD21F015E90517672F1553724DDA"
                                      ++ "12692D23EC7E0B420A93D249C4383566"
                                      ++ "22D45809034A1A92B3DE34AEB4421168" )
                          , ((256, 319), "14DEA7F82A4D3C1796C3911ABC2EFE9D"
                                      ++ "C9EB79C42F72691F8CB8C353ECBCC0DC"
                                      ++ "6159EC13DFC08442F99F0F68355D704E"
                                      ++ "5649D8B34836B5D2C46F8999CD570B17" )
                          , ((448, 511), "CA6A357766527EA439B56C970E2E089C"
                                      ++ "30C94E62CB07D7FE1B1403540C2DA9A6"
                                      ++ "362732811EF811C9D04ED4880DC0038D"
                                      ++ "5FDCE22BDE2668CD75107D7926EC98B5" )
                          ]
    , testVector128 "Set 3, vector# 27"  "1B1C1D1E1F202122232425262728292A"
                                         "0000000000000000"
                          [ ((0, 63),    "E04A423EF2E928DCA81E10541980CDE5"
                                      ++ "C8054CC3CF437025B629C13677D41167"
                                      ++ "21123EE13F889A991C03A2E5ADC0B12B"
                                      ++ "9BBC63CB60A23543445919AF49EBC829" )
                          , ((192, 255), "F6E1D7DBD22E05430EBFBEA15E751C83"
                                      ++ "76B4743681DE6AC3E257A3C3C1F9EC6A"
                                      ++ "63D0A04BF3A07F64E6B167A49CD3FDAA"
                                      ++ "B89A05E438B1847E0DC6E9108A8D4C71" )
                          , ((256, 319), "FC2B2A1A96CF2C73A8901D334462ED56"
                                      ++ "D57ABD985E4F2210D7366456D2D1CDF3"
                                      ++ "F99DFDB271348D00C7E3F51E6738218D"
                                      ++ "9CD0DDEFF12341F295E762C50A50D228" )
                          , ((448, 511), "1F324485CC29D2EAEC7B31AE7664E8D2"
                                      ++ "C97517A378A9B8184F50801524867D37"
                                      ++ "6652416A0CA96EE64DDF26138DB5C58A"
                                      ++ "3B22EF9037E74A9685162EE3DB174A0E" )
                          ]
    , testVector128 "Set 3, vector# 36"  "2425262728292A2B2C2D2E2F30313233"
                                         "0000000000000000"
                          [ ((0, 63),    "361A977EEB47543EC9400647C0C16978"
                                      ++ "4C852F268B34C5B163BCA81CFC5E746F"
                                      ++ "10CDB464A4B1365F3F44364331568DB2"
                                      ++ "C4707BF81AA0E0B3AB585B9CE6621E64" )
                          , ((192, 255), "E0F8B9826B20AEEC540EABA9D12AB8EB"
                                      ++ "636C979B38DE75B87102C9B441876C39"
                                      ++ "C2A5FD54E3B7AB28BE342E377A328895"
                                      ++ "6C1A2645B6B76E8B1E21F871699F627E" )
                          , ((256, 319), "850464EEED2251D2B5E2FE6AE2C11663"
                                      ++ "E63A02E30F59186172D625CFF2A646FA"
                                      ++ "CB85DC275C7CA2AF1B61B95F22A5554F"
                                      ++ "BAD63C0DCC4B5B333A29D270B6366AEF" )
                          , ((448, 511), "4387292615C564C860AE78460BBEC30D"
                                      ++ "ECDFBCD60AD2430280E3927353CEBC21"
                                      ++ "DF53F7FD16858EF7542946442A26A1C3"
                                      ++ "DA4CEFF5C4B781AD6210388B7905D2C7" )
                          ]
    , testVector128 "Set 3, vector# 45"  "2D2E2F303132333435363738393A3B3C"
                                         "0000000000000000"
                          [ ((0, 63),    "9F25D8BD7FBC7102A61CB590CC69D1C7"
                                      ++ "2B31425F11A685B80EAC771178030AF0"
                                      ++ "52802311ED605FF07E81AD7AAC79B6A8"
                                      ++ "1B24113DB5B4F927E6481E3F2D750AB2" )
                          , ((192, 255), "DAEF37444CB2B068124E074BAD188195"
                                      ++ "3D61D5BA3BFBF37B21BC47935D74820E"
                                      ++ "9187086CEF67EB86C88DDD62C48B9089"
                                      ++ "A9381750DC55EA4736232AE3EDB9BFFE" )
                          , ((256, 319), "B6C621F00A573B60571990A95A4FEC4A"
                                      ++ "C2CA889C70D662BB4FF54C8FAAE0B7C4"
                                      ++ "5B8EC5414AE0F080B68E2943ABF76EA2"
                                      ++ "ABB83F9F93EF94CB3CFE9A4CEED337CD" )
                          , ((448, 511), "6F17EAE9346878BB98C97F6C81DD2E41"
                                      ++ "5FDEB54305FE2DF74AFC65627C376359"
                                      ++ "FB2E7841FF75744A715DF952851C1CBC"
                                      ++ "DD241BADF37B3618E0097B3A084E1B54" )
                          ]
    , testVector128 "Set 3, vector# 54"  "363738393A3B3C3D3E3F404142434445"
                                         "0000000000000000"
                          [ ((0, 63),    "3466360F26B76484D0C4FD63965E5561"
                                      ++ "8BDBFDB2213D8CA5A72F2FE6E0A13548"
                                      ++ "D06E87C8A6EEA392FE52D3F5E0F6559D"
                                      ++ "331828E96A07D99C6C0A42EFC24BA96D" )
                          , ((192, 255), "AB7184066D8E0AB537BB24D777088BC4"
                                      ++ "41E00481834B5DD5F6297D6F221532BC"
                                      ++ "56F638A8C84D42F322767D3D1E11A3C6"
                                      ++ "5085A8CA239A4FDD1CDF2AC72C1E354F" )
                          , ((256, 319), "55F29F112B07544EDA3EBB5892DBB91E"
                                      ++ "46F8CBC905D0681D8E7109DF816ABFB8"
                                      ++ "AE6A0F9833CDF34A29F25D67A60D3633"
                                      ++ "8A10346FEBE72CCF238D8670C9F2B59C" )
                          , ((448, 511), "0657453B7806D9EA777FFFBE05028C76"
                                      ++ "DCFF718BC9B6402A3CAEC3BCCB7231E6"
                                      ++ "D3DDB00D5A9637E1E714F47221FFCC11"
                                      ++ "B1425D9653F7D777292B146556A89787" )
                          ]
    , testVector128 "Set 3, vector# 63"  "3F404142434445464748494A4B4C4D4E"
                                         "0000000000000000"
                          [ ((0, 63),    "40AD59C99464D95702727406E4C82C85"
                                      ++ "7FA48911319A3FCC231DC91C990E19D4"
                                      ++ "D9D5972B6A6F21BD12C118365ECAABC8"
                                      ++ "9F9C3B63FFF77D8EA3C55B2322B57D0E" )
                          , ((192, 255), "DBF23042C787DDF6FFCE32A792E39DF9"
                                      ++ "E0332B0A2A2F2A5F96A14F51FAAB7C27"
                                      ++ "14E07C3ADCA32D0DE5F8968870C7F0E8"
                                      ++ "1FE263352C1283965F8C210FC25DE713" )
                          , ((256, 319), "455E3D1F5F44697DA562CC6BF77B9309"
                                      ++ "9C4AFAB9F7F300B44AD9783A9622BD54"
                                      ++ "3EFDB027D8E71236B52BEE57DD2FB3EE"
                                      ++ "1F5B9022AB96A59AE7DF50E6933B3209" )
                          , ((448, 511), "F11D47D8C57BBF862E0D6238BC0BF6A5"
                                      ++ "2500A62BB037B3A33E87525259B8E547"
                                      ++ "35F664FCEDF11BA2C0F3AEB9C944BCE7"
                                      ++ "7FFD26D604674DF8905A73CB7E230A4F" )
                          ]
    , testVector128 "Set 3, vector# 72"  "48494A4B4C4D4E4F5051525354555657"
                                         "0000000000000000"
                          [ ((0, 63),    "D8B1A4CB2A5A8DE1F798254A41F61DD4"
                                      ++ "FB1226A1B4C62FD70E87B6ED7D57902A"
                                      ++ "69642E7E21A71C6DC6D5430DCE89F16F"
                                      ++ "CCC9AAD48743974473753A6FF7663FD9" )
                          , ((192, 255), "D4BA9BC857F74A28CACC734844849C3E"
                                      ++ "DCB9FB952023C97E80F5BFA445178CAB"
                                      ++ "92B4D9AA8A6D4E79B81993B831C73765"
                                      ++ "10E74E30E7E68AD3188F8817DA8243F2" )
                          , ((256, 319), "B7039E6F6C4D5D7F750ED014E6501188"
                                      ++ "17994F0D3C31B071CC16932A412E627D"
                                      ++ "2486CCB9E43FCA79039D3E0F63577406"
                                      ++ "F5B6420F5587CF9DAC40118AA6F170A8" )
                          , ((448, 511), "1ABA14E7E9E6BA4821774CBC2B63F410"
                                      ++ "381E4D661F82BAB1B182005B6D42900D"
                                      ++ "C658C6224F959E05095BC8081920C8AD"
                                      ++ "11148D4F8BD746B3F0059E15C47B9414" )
                          ]
    , testVector128 "Set 3, vector# 81"  "5152535455565758595A5B5C5D5E5F60"
                                         "0000000000000000"
                          [ ((0, 63),    "235E55E2759C6781BBB947133EDD4D91"
                                      ++ "C9746E7E4B2E5EF833A92BE6086C57C6"
                                      ++ "729655D4C4253EC17ACF359012E80175"
                                      ++ "7E7A6EB0F713DEC40491266604B83311" )
                          , ((192, 255), "247BEAAC4A785EF1A55B469A1AEE8530"
                                      ++ "27B2D37C74B8DA58A8B92F1360968513"
                                      ++ "C0296585E6745E727C34FFCE80F5C72F"
                                      ++ "850B999721E3BF1B6C3A019DBEE464C1" )
                          , ((256, 319), "E7DDB25678BF6EECA2DA2390C9F333EB"
                                      ++ "61CD899DD823E7C19474643A4DA31335"
                                      ++ "2556E44A9C0006C8D54B1FD0313D574A"
                                      ++ "08B86138394BA1194E140A62A96D7F01" )
                          , ((448, 511), "DB417F9C1D9FD49FC96DB5E981F0C3F8"
                                      ++ "484E3BDC559473963D12D982FEA287A3"
                                      ++ "9A36D69DDBBCF1CA2C9FB7F4B2B37F3D"
                                      ++ "A755838A67C48822F4C1E82E65A07151" )
                          ]
    , testVector128 "Set 3, vector# 90"  "5A5B5C5D5E5F60616263646566676869"
                                         "0000000000000000"
                          [ ((0, 63),    "F27A0A59FA3D1274D934EACCFA0038AF"
                                      ++ "C3B866D2BFA4A8BA81D698DBCA5B65D5"
                                      ++ "2F3A1AC9855BEEEB3B41C510F7489E35"
                                      ++ "AB22CB4444816208C282C461FF16A7BC" )
                          , ((192, 255), "522594154A2E4843083ABCA886102DA8"
                                      ++ "14500C5AADAAB0C8FB40381B1D750F9D"
                                      ++ "A9A1831D8000B30BD1EFA854DC903D63"
                                      ++ "D53CD80A10D642E332DFFC9523792150" )
                          , ((256, 319), "5D092D8E8DDA6C878A3CFBC1EC8DD13F"
                                      ++ "2A1B073916097AEC4C3E56A229D8E282"
                                      ++ "DDB656DAD60DBC7DF44DF124B19920FC"
                                      ++ "C27FCADB1782F1B73E0A78C161270700" )
                          , ((448, 511), "8F75BF72995AD23E9ADFEA351F26E42B"
                                      ++ "E2BE8D67FB810ABCBD5FAE552DC10D1E"
                                      ++ "281D94D5239A4EA311784D7AC7A764FA"
                                      ++ "88C7FD7789E803D11E65DD6AC0F9E563" )
                          ]
    , testVector128 "Set 3, vector# 99"  "636465666768696A6B6C6D6E6F707172"
                                         "0000000000000000"
                          [ ((0, 63),    "654037B9120AEB60BD08CC07FFEC5985"
                                      ++ "C914DAD04CD1277312B4264582A4D85A"
                                      ++ "4CB7B6CC0EB8AD16475AD8AE99888BC3"
                                      ++ "FDE6A5B744851C5FC77EAB50CFAD021D" )
                          , ((192, 255), "E52D332CD0DE31F44CDCAB6C71BD38C9"
                                      ++ "4417870829D3E2CFDAC40137D066EA48"
                                      ++ "2786F146137491B8B9BC05675C4F88A8"
                                      ++ "B58686E18D63BE71B6FEFEF8E46D0273" )
                          , ((256, 319), "28959548CE505007768B1AA6867D2C00"
                                      ++ "9F969675D6E6D54496F0CC1DC8DD1AFB"
                                      ++ "A739E8565323749EAA7B03387922C50B"
                                      ++ "982CB8BC7D602B9B19C05CD2B87324F9" )
                          , ((448, 511), "D420AEC936801FEE65E7D6542B37C919"
                                      ++ "0E7DB10A5934D3617066BEA8CC80B8EA"
                                      ++ "AAFC82F2860FA760776418B4FF148DFD"
                                      ++ "58F21D322909E7BF0EC19010A168FAF7" )
                          ]
    , testVector128 "Set 3, vector#108"  "6C6D6E6F707172737475767778797A7B"
                                         "0000000000000000"
                          [ ((0, 63),    "0DB7EA55A79C045818C29E99D8A4B664"
                                      ++ "33E4C77DF532D71BA720BD5D82629F12"
                                      ++ "76EF0BF93E636A6F71F91B947DFA7CAA"
                                      ++ "A1B0512AA531603197B86ABA2B0829D1" )
                          , ((192, 255), "A62EAFD63CED0D5CE9763609697E78A7"
                                      ++ "59A797868B94869EC54B44887D907F01"
                                      ++ "542028DEDDF420496DE84B5DA9C6A401"
                                      ++ "2C3D39DF6D46CE90DD45AF10FA0F8AAF" )
                          , ((256, 319), "7C2AD3F01023BC8E49C5B36AFE7E67DC"
                                      ++ "A26CCD504C222BD6AF467D4C6B07B792"
                                      ++ "61E9714FDD1E35C31DA4B44DB8D4FC05"
                                      ++ "69F885F880E63B5ABB6BA0BFEE2CE80C" )
                          , ((448, 511), "066D3C8D46F45891430A85852FF53744"
                                      ++ "8EBDD6CE8A799CCF7EAF88425FBD60D3"
                                      ++ "2A1741B39CC3C73371C2C9A36544D3C3"
                                      ++ "B0F02D2596ACC61C60A6671F112F185E" )
                          ]
    , testVector128 "Set 3, vector#117"  "75767778797A7B7C7D7E7F8081828384"
                                         "0000000000000000"
                          [ ((0, 63),    "3FE4BD60364BAB4F323DB8097EC189E2"
                                      ++ "A43ACD0F5FFA5D65D8BDB0D79588AA9D"
                                      ++ "86669E143FD5915C31F7283F1180FCAB"
                                      ++ "CDCB64B680F2B63BFBA2AF3FC9836307" )
                          , ((192, 255), "F1788B6CA473D314F6310675FC716252"
                                      ++ "8285A538B4C1BE58D45C97349C8A3605"
                                      ++ "7774A4F0E057311EEA0D41DFDF131D47"
                                      ++ "32E2EAACA1AB09233F8124668881E580" )
                          , ((256, 319), "FEF434B35F024801A77400B31BD0E735"
                                      ++ "22BEC7D10D8BF8743F991322C660B4FD"
                                      ++ "2CEE5A9FDE0D614DE8919487CBD5C6D1"
                                      ++ "3FEB55C254F96094378C72D8316A8936" )
                          , ((448, 511), "338FD71531C8D07732FD7F9145BBC368"
                                      ++ "932E3F3E4C72D2200A4F780AF7B2C3AA"
                                      ++ "91C1ED44DBEAA9A2F1B3C64DCE8DCD27"
                                      ++ "B307A4104D5C755693D848BEA2C2D23B" )
                          ]
    , testVector128 "Set 3, vector#126"  "7E7F808182838485868788898A8B8C8D"
                                         "0000000000000000"
                          [ ((0, 63),    "062187DAA84742580D76E1D55EE4DE2E"
                                      ++ "3B0C454F383CFDDE567A008E4E8DAA3C"
                                      ++ "E645D5BEDA64A23F0522D8C15E6DA0AD"
                                      ++ "88421577A78F2A4466BD0BFA243DA160" )
                          , ((192, 255), "4CC379C5CF66AA9FB0850E50ED8CC58B"
                                      ++ "72E8441361904449DAABF04D3C464DE4"
                                      ++ "D56B22210B4336113DAA1A19E1E15339"
                                      ++ "F047DA5A55379C0E1FE448A20BC10266" )
                          , ((256, 319), "BD2C0F58DBD757240AEB55E06D5526FE"
                                      ++ "7088123CE2F7386699C3E2780F5C3F86"
                                      ++ "374B7CB9505299D639B89D7C717BA8A2"
                                      ++ "AEED0C529F22F8C5006913D1BE647275" )
                          , ((448, 511), "54D61231409D85E46023ED5EFF8FDC1F"
                                      ++ "7A83CACDDB82DD8D1FA7CDEA0E088A61"
                                      ++ "D02BCE7FA7EC3B73B66953DA467BE4B9"
                                      ++ "12EBE2A46B56A8BF0D925A919B7B22E3" )
                          ]
    , testVector128 "Set 3, vector#135"  "8788898A8B8C8D8E8F90919293949596"
                                         "0000000000000000"
                          [ ((0, 63),    "1A74C21E0C929282548AD36F5D6AD360"
                                      ++ "E3A9100933D871388F34DAFB286471AE"
                                      ++ "D6ACC48B470476DC5C2BB593F59DC17E"
                                      ++ "F772F56922391BF23A0B2E80D65FA193" )
                          , ((192, 255), "B9C8DAC399EF111DE678A9BD8EC24F34"
                                      ++ "0F6F785B19984328B13F78072666955A"
                                      ++ "B837C4E51AC95C36ECBEFFC07D9B37F2"
                                      ++ "EE9981E8CF49FD5BA0EADDE2CA37CC8D" )
                          , ((256, 319), "3B0283B5A95280B58CEC0A8D65328A7A"
                                      ++ "8F3655A4B39ECBE88C6322E93011E13C"
                                      ++ "FF0A370844851F4C5605504E8266B301"
                                      ++ "DD9B915CA8DCD72E169AEA2033296D7F" )
                          , ((448, 511), "4F9CA1676901DDC313D4EE17B815F6B5"
                                      ++ "AC11AF03BF02517FB3B10E9302FCBF67"
                                      ++ "C284B5C7612BBE7249365BCAC07FD4C2"
                                      ++ "C7AE78F3FDA1880B2DAA20E4EC70F93B" )
                          ]
    , testVector128 "Set 3, vector#144"  "909192939495969798999A9B9C9D9E9F"
                                         "0000000000000000"
                          [ ((0, 63),    "0281FB6B767A90231AB6A19EB1E4FB76"
                                      ++ "A041063FE23AC835797DFA178CC2D7C2"
                                      ++ "8DFAD591D2EAF26A985332F8DC74537D"
                                      ++ "F7E0A5F26946BCF7D70B6C3D9DD859D2" )
                          , ((192, 255), "088ED6D7AB26EEC97518EBF387B0644F"
                                      ++ "D22266E578F141A7218F94AE2EE5885A"
                                      ++ "67A9FA304F6880A781EE05C1251A7EAD"
                                      ++ "4C3025D833B59739C68D3D7F3A844148" )
                          , ((256, 319), "6B48D13EC0EB1CD0CDAC5D5E09DC7BE4"
                                      ++ "AE02BE4283DDC7FA68E802A31508E6EA"
                                      ++ "7197E5AC10805FDEB6824AEEF8178BAA"
                                      ++ "45D7E419CF9237155D379B38F994EF98" )
                          , ((448, 511), "7E71823935822D048B67103FF56A709A"
                                      ++ "25517DCE5CFBB807B496EEF79EFFBCD1"
                                      ++ "0D23BAD02758814F593B2CD4AC062699"
                                      ++ "AEC02B25A7E0D1BAE598AFDBE4333FE7" )
                          ]
    , testVector128 "Set 3, vector#153"  "999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8"
                                         "0000000000000000"
                          [ ((0, 63),    "D4ACE9BF4A76822D685E93E7F77F2A79"
                                      ++ "46A76E3BF0910854C960331A41835D40"
                                      ++ "902BC1CF3F8A30D4C8391087EC3A03D8"
                                      ++ "81E4734A5B830EFD55DA84159879D97F" )
                          , ((192, 255), "5BD8BB7ED009652150E62CF6A17503BA"
                                      ++ "E55A9F4ECD45B5E2C60DB74E9AE6C8BF"
                                      ++ "44C71000912442E24ED2816243A7794D"
                                      ++ "5B1203A246E40BE02F285294399388B1" )
                          , ((256, 319), "55433BDEA349E8849D7DF899193F029A"
                                      ++ "9F09405D7AFE842CB2C79F0E55C88913"
                                      ++ "B0776825D8D036A69DDDCD6AFCA6588F"
                                      ++ "69F0946A86D32C3585F3813B8CCB56AF" )
                          , ((448, 511), "0B67F00FA0BB7D1ED5E4B46A68794864"
                                      ++ "5239422656F77EF2AFEA34FFF98DA7A8"
                                      ++ "90970F09137AF0FABD754C296DD3C6F2"
                                      ++ "7539BC3AE78FFA6CDCCC75E944660BB4" )
                          ]
    , testVector128 "Set 3, vector#162"  "A2A3A4A5A6A7A8A9AAABACADAEAFB0B1"
                                         "0000000000000000"
                          [ ((0, 63),    "92A067C3724F662120C25FAF4B9EC419"
                                      ++ "C392D98E5CB8C5EE5842C1D5C704DE87"
                                      ++ "8C8C68C55BA83D63C5DEEC24CFF7230D"
                                      ++ "3F6FBF6E49520C20CFE422798C676A47" )
                          , ((192, 255), "133C9A30B917C583D84FB0AAC2C63B5F"
                                      ++ "6758AC8C2951196E9460ADBE3417D914"
                                      ++ "90F0A195DC5682F984069506CA75DC1D"
                                      ++ "79A7AE1DCDF9E0219D4E6A005BA72EDD" )
                          , ((256, 319), "091D38749503B63238B1E3260855B76C"
                                      ++ "5CFE9D012265FB7F58EB8CAA76B45645"
                                      ++ "9C54F051274DDAE06BEC6D7EB8B9FF59"
                                      ++ "5302D9D68F2AF1057581D5EE97CCEEDD" )
                          , ((448, 511), "3FCCB960792B7136768BBA4C3D69C597"
                                      ++ "88F04602C10848A7BCBED112F860998D"
                                      ++ "9E9A788998D1DC760F7ECF40597446D8"
                                      ++ "F39CD4D4013F472BB125DE6A43E9799D" )
                          ]
    , testVector128 "Set 3, vector#171"  "ABACADAEAFB0B1B2B3B4B5B6B7B8B9BA"
                                         "0000000000000000"
                          [ ((0, 63),    "AC3DE1B9F6DF6D6117B671A639BF0761"
                                      ++ "24A0A6D293B107554E9D662A8BFC3F34"
                                      ++ "17C59437C981A0FDF9853EDF5B9C38FE"
                                      ++ "74072C8B78FE5EBA6B8B970FE0CE8F1F" )
                          , ((192, 255), "23112BD4E7F978D15F8B16F6EDB130D7"
                                      ++ "2F377233C463D710F302B9D7844C8A47"
                                      ++ "FB2DFDD60235572859B7AF100149C87F"
                                      ++ "6ED6CE2344CDF917D3E94700B05E2EEF" )
                          , ((256, 319), "E8DDFE8916B97519B6FCC881AEDDB42F"
                                      ++ "39EC77F64CAB75210B15FBE104B02FC8"
                                      ++ "02A775C681E79086D0802A49CE6212F1"
                                      ++ "77BF925D10425F7AD199AB06BD4D9802" )
                          , ((448, 511), "F9D681342E65348868500712C2CA8481"
                                      ++ "D08B7176A751EF880014391A54680992"
                                      ++ "6597B10E85761664558F34DA486D3D44"
                                      ++ "54829C2D337BBA3483E62F2D72A0A521" )
                          ]
    , testVector128 "Set 3, vector#180"  "B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3"
                                         "0000000000000000"
                          [ ((0, 63),    "21BD228837BFB3ACB2DFC2B6556002B6"
                                      ++ "A0D63A8A0637533947615E61FE567471"
                                      ++ "B26506B3D3B23F3FDB90DFAC6515961D"
                                      ++ "0F07FD3D9E25B5F31B07E29657E000BF" )
                          , ((192, 255), "2CF15E4DC1192CA86AA3B3F64841D8C5"
                                      ++ "CD7067696674B6D6AB36533284DA3ABF"
                                      ++ "D96DD87830AE8FA723457BE53CB3404B"
                                      ++ "7A0DCBB4AF48A40FC946C5DEB7BD3A59" )
                          , ((256, 319), "E3B15D2A87F61C2CE8F37DCEB896B5CA"
                                      ++ "28D1DA6A3A71704309C0175BB6116911"
                                      ++ "9D5CBE34FC8F052961FF15F2C8F06CD6"
                                      ++ "F8E889694E2C69E918DD29C33F125D31" )
                          , ((448, 511), "CCD1C951D6339694972E902166A13033"
                                      ++ "A1B0C07313DC5927FE9FB3910625332C"
                                      ++ "4F0C96A8896E3FC26EFF2AF9484D28B8"
                                      ++ "CB36FF4883634B40C2891FA53B6620B1" )
                          ]
    , testVector128 "Set 3, vector#189"  "BDBEBFC0C1C2C3C4C5C6C7C8C9CACBCC"
                                         "0000000000000000"
                          [ ((0, 63),    "7943AD4AA5F62E08E1AE450E84CFF27D"
                                      ++ "E3B204A2BCA315B981906D5A13F68AB0"
                                      ++ "34D3396EA8A41001AF49834368805B37"
                                      ++ "D5380FB14821E3F7F4B44231784306F3" )
                          , ((192, 255), "415F5381C9A58A29045E77A1E91E6726"
                                      ++ "DFCEBC71E4F52B36DBD7432D158F2ADB"
                                      ++ "31CF5F52D8456952C09B45A16B289B7A"
                                      ++ "32687716B8EDFF0B1E5D0FC16DCCFA88" )
                          , ((256, 319), "CE317CB853E2AFA22392D4B8AE345A91"
                                      ++ "0807F8DE3A14A820CDA771C2F2F3629A"
                                      ++ "65A1CC7A54DDEC182E29B4DACEA5FBFA"
                                      ++ "4FAC8F54338C7B854CD58ABA74A2ACFF" )
                          , ((448, 511), "5804F61C5C07EC3C2D37DF746E4C96A1"
                                      ++ "AD5E004C2585F3F401CB3AF62CB975F8"
                                      ++ "64375BE3A7117079810418B07DABCCEE"
                                      ++ "61B6EC98EA4F28B0D88941CB6BE2B9D2" )
                          ]
    , testVector128 "Set 3, vector#198"  "C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5"
                                         "0000000000000000"
                          [ ((0, 63),    "A4FB9A02500A1F86145956E16D04975E"
                                      ++ "2A1F9D2283D8AD55C17A9BD6E0C8B561"
                                      ++ "6658132B8928F908FEC7C6D08DBFBC55"
                                      ++ "73449F28AA0EF2884E3A7637233E45CD" )
                          , ((192, 255), "74D169573560C14692BBE2498FDA0ED7"
                                      ++ "866A11EE4F26BB5B2E9E2559F089B35E"
                                      ++ "C9972634C5A969DD16EB4341782C6C29"
                                      ++ "FBBF4D11ECB4133D1F9CA576963973EB" )
                          , ((256, 319), "D28966E675759B82EDE324ABA1121B82"
                                      ++ "EAB964AB3E10F0FE9DF3FCC04AFC8386"
                                      ++ "3A43FD6B7FC0AD592C93B80BE99207CB"
                                      ++ "A8A55DDEA56DD811AAD3560B9A26DE82" )
                          , ((448, 511), "E362A817CCD304126E214D7A0C8E9EB9"
                                      ++ "3B33EB15DE324DDDFB5C870EA22279C7"
                                      ++ "8E28EFF95974C2B935FC9F1BF531D372"
                                      ++ "EF7244D2CC620CEBDE5D8096AD7926B3" )
                          ]
    , testVector128 "Set 3, vector#207"  "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE"
                                         "0000000000000000"
                          [ ((0, 63),    "FF879F406EAF43FABC6BE563ADA47C27"
                                      ++ "872647F244C7FAE428E4130F17B47138"
                                      ++ "0E1E1CD06C50309760FDEE0BC91C31D0"
                                      ++ "CA797E07B173C6202D2916EEBA9B6D1C" )
                          , ((192, 255), "61E724B288AECF393483371C1BE653F3"
                                      ++ "7BBA313D220173A43459F0BCE195E45C"
                                      ++ "49B3B5FB1B0539DE43B5B4F2960D8E6E"
                                      ++ "5BC81DAF07E9EFBB760881441FA8823B" )
                          , ((256, 319), "F77AC22945ECD60EBCAF4BA19A59B078"
                                      ++ "B3C3BC36D1DDA6B9969B458C2019D68E"
                                      ++ "FD04D75DDC6041BBCD69747651D2DA7F"
                                      ++ "BED721081F8147367585CABB1C50CF0C" )
                          , ((448, 511), "7475DCD3545B810445AFCA0C0AFA93A9"
                                      ++ "11EA99991A5D639AB32DDF69AA21C45A"
                                      ++ "53DCB998FDAE5F9A82EC8501123EAE3D"
                                      ++ "99351C43311F8430DB3D230E12DA77D2" )
                          ]
    , testVector128 "Set 3, vector#216"  "D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7"
                                         "0000000000000000"
                          [ ((0, 63),    "2B4C4185E2FDFAE75DABFF32632FB5D9"
                                      ++ "823359F15E2D17FF74FAC844E5016A4A"
                                      ++ "64C2C47498A15029FBEB6E4893381E65"
                                      ++ "6D2A2B9712524827B151C6E67D990388" )
                          , ((192, 255), "D870A94C4856EF818C5D93B2187F09C7"
                                      ++ "32E4491103B8A49B14CDC118F1607E2D"
                                      ++ "8443740F20220DF076B981D90436E9C3"
                                      ++ "09282C1CEAAE6375002AD1CA9CCF720C" )
                          , ((256, 319), "5091AE53E13948DAE57F6B0BE95B8F46"
                                      ++ "A1F53553767B98F9799A0F0AC468AEB3"
                                      ++ "40C20E23FA1A8CAE7387CEA127A7A0F3"
                                      ++ "635667BF028DE15179093B706306B99C" )
                          , ((448, 511), "02323B1FA2C863D3B4A89CFC143013A6"
                                      ++ "EEA8265BBD1B8FE243DEA2F4B19A5726"
                                      ++ "593564E7E7021FD042F58077A5821C2F"
                                      ++ "415BC38D6DD2BE29A5400E4B1D65B2A2" )
                          ]
    , testVector128 "Set 3, vector#225"  "E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0"
                                         "0000000000000000"
                          [ ((0, 63),    "9A5509AB6D2AB05C7DBA61B0CC9DD844"
                                      ++ "B352A293E7D96B5C0066ACDB548DB857"
                                      ++ "0459E989B83AF10A2C48E9C00E02671F"
                                      ++ "436B39C174494787D1ECEB3417C3A533" )
                          , ((192, 255), "8A913EBA25B4D5B485E67F97E83E10E0"
                                      ++ "B858780D482A6840C88E7981F59DC51F"
                                      ++ "2A86109E9CD526FCFA5DBF30D4AB5753"
                                      ++ "51027E5A1C923A00007260CE7948C53D" )
                          , ((256, 319), "0A901AB3EBC2B0E4CBC154821FB7A0E7"
                                      ++ "2682EC9876144C4DC9E05098B6EFCCCB"
                                      ++ "90E2F03837553C579CDD0A647D6A6963"
                                      ++ "50000CA57628B1E48E96242226A92ECC" )
                          , ((448, 511), "9CDB39B79A464F2CCA3637F04EBAEA35"
                                      ++ "7A229FC6A9BA5B83171A0A8945B6F117"
                                      ++ "56EBC9F4201D0BA09C39F97767213046"
                                      ++ "32AA6A68ADE5B90268AEE335E13B1D39" )
                          ]
    , testVector128 "Set 3, vector#234"  "EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9"
                                         "0000000000000000"
                          [ ((0, 63),    "37EDAFA4F5EDC64EBF5F74E543493A53"
                                      ++ "93353DE345A70467A9EC9F61EEFE0ED4"
                                      ++ "532914B3EA6C2D889DA9E22D45A7DD32"
                                      ++ "1EA5F1F6978A7B2E2A15D705DE700CE4" )
                          , ((192, 255), "C415739777C22430DAB2037F6287E516"
                                      ++ "B1CE142111456D8919E8CD19C2B2D30D"
                                      ++ "8A1B662C26137F20F87C2802A2F3E66D"
                                      ++ "8CEB9D3C1B4368195856249A379BD880" )
                          , ((256, 319), "0381733EC9B2073F9E4E995447118411"
                                      ++ "2D99B23FA4A87B4025C6AF955E93E0D5"
                                      ++ "7DD37011E1624175F970BDA7D625224B"
                                      ++ "AB0F021E6453DBA894A5074C447D24BC" )
                          , ((448, 511), "F9D45C7E0E7A26F2E7E2C07F68AF1191"
                                      ++ "CC699964C01654522924A98D6790A946"
                                      ++ "A04CD9586455D5A537CBA4D10B3C2718"
                                      ++ "745C24875156483FE662B11E0634EAEA" )
                          ]
    , testVector128 "Set 3, vector#243"  "F3F4F5F6F7F8F9FAFBFCFDFEFF000102"
                                         "0000000000000000"
                          [ ((0, 63),    "B935A7B6D798932D879795A182E7C194"
                                      ++ "BECEFF32522C2F3FFF55A5C6D32A91D2"
                                      ++ "BA9F144DB280ABA7BA8A7921AFA3BD82"
                                      ++ "CA742DDBEAF8AF72299936E9C2FEA59E" )
                          , ((192, 255), "6F32248B6EF4CDAE06864B6477893440"
                                      ++ "F0E0217421D7081D1F0DA197B5263674"
                                      ++ "0E9BDD59068BEDE48BF52C43446C12CD"
                                      ++ "4F10ED22BFDDFA915FA0FB1A73F9139C" )
                          , ((256, 319), "BF01A4ED868EF9080DF80689E589897C"
                                      ++ "021DCA18073F9291E1D158DC26266556"
                                      ++ "728DD130629D3760F541439147F4C1CA"
                                      ++ "279FB98040E9FCE50998E42D6259DE1F" )
                          , ((448, 511), "0F2B116CD687C91FBA1EDEAD586411E9"
                                      ++ "66D9EA1076863EC3FDFC254DD5C93ED6"
                                      ++ "AE1B01982F63A8EB13D839B2510AD02C"
                                      ++ "DE24210D97A7FA9623CAC00F4C5A1107" )
                          ]
    , testVector128 "Set 3, vector#252"  "FCFDFEFF000102030405060708090A0B"
                                         "0000000000000000"
                          [ ((0, 63),    "09D36BFFDDCD3ADC8EB0ABEEB3794CE1"
                                      ++ "FFBDED9CFC315D21A53C221B27722FE3"
                                      ++ "F10E20D47DDCFD3CCDE9C1BAAF01F551"
                                      ++ "1D3F14F88BF741A7F6578C3BC9024B2B" )
                          , ((192, 255), "552502A1B2D0F29806DE512F3314FC8E"
                                      ++ "19518E35D9DB1EBC9034EA46E5815AB9"
                                      ++ "DF0F403E997E676BF47C0116D5E9B817"
                                      ++ "26B99D65AA4315F1E5906F6E39B1297E" )
                          , ((256, 319), "6BF351A501E8D1B4BAF4BFD04726DC4F"
                                      ++ "50200463DCC13FF3BE93E6C4D4304CE0"
                                      ++ "9E6A1CEA41BFB93D6DBAD713298F79CF"
                                      ++ "F6F5BB81F456E33A3396D02F2E33BDC5" )
                          , ((448, 511), "715F8FFB2BC25CD89E46B706EF871207"
                                      ++ "EFE736AA3CB961B06E7B439E8E4F76E2"
                                      ++ "944AF7BD49EEC47B4A2FD716D191E858"
                                      ++ "59C74FD0B4A505ACE9F80EEB39403A1F" )
                          ]
    , testVector128 "Set 4, vector#  0"  "0053A6F94C9FF24598EB3E91E4378ADD"
                                         "0000000000000000"
                          [ ((0, 63),    "BE4EF3D2FAC6C4C3D822CE67436A407C"
                                      ++ "C237981D31A65190B51053D13A19C89F"
                                      ++ "C90ACB45C8684058733EDD259869C58E"
                                      ++ "EF760862BEFBBCA0F6E675FD1FA25C27" )
                      , ((65472, 65535), "F5666B7BD1F4BC8134E0E45CDB69876D"
                                      ++ "1D0ADAE6E3C17BFBFE4BCE02461169C5"
                                      ++ "4B787C6EF602AF92BEBBD66321E0CAF0"
                                      ++ "44E1ADA8CCB9F9FACFC4C1031948352E" )
                      , ((65536, 65599), "292EEB202F1E3A353D9DC6188C5DB434"
                                      ++ "14C9EF3F479DF988125EC39B30C014A8"
                                      ++ "09683084FBCDD5271165B1B1BF54DAB4"
                                      ++ "40577D864CD186867876F7FDA5C79653" )
                    , ((131008, 131071), "C012E8E03878A6E7D236FEC001A9F895"
                                      ++ "B4F58B2AF2F3D237A944D93273F5F3B5"
                                      ++ "45B1220A6A2C732FC85E7632921F2D36"
                                      ++ "6B3290C7B0A73FB61D49BC7616FC02B8" )
                          ]
    , testVector128 "Set 4, vector#  1"  "0558ABFE51A4F74A9DF04396E93C8FE2"
                                         "0000000000000000"
                          [ ((0, 63),    "BA1A48247B8C44AAF12F5645D65FF7F4"
                                      ++ "E4D7C404EE0CBB691355FAEB82D03B99"
                                      ++ "AD0FDFC20A1E593973E5B8F0264F7FB0"
                                      ++ "538292A4C8FE8218A1DA3EB7B71EEA64" )
                      , ((65472, 65535), "03A24E89D69D5E1DA98B0367CF626F33"
                                      ++ "D558B1208AB120B6B1778BFF640F56DA"
                                      ++ "715FE1B681D8CC0F305D6645B439BA81"
                                      ++ "D3C446A428B31BB18E9DA1E2A900B0FD" )
                      , ((65536, 65599), "6A28ADD4F926759CEBB0AFC5D5DA5243"
                                      ++ "1F2E7ECBBD1E9DEAF368137E35F1AFBD"
                                      ++ "65852214FA06310C3175FCF364810F62"
                                      ++ "7E3703E9AC5458A8B681EB03CEECD872" )
                    , ((131008, 131071), "E8D8AB5E245B9A83A77B30F19E3706F0"
                                      ++ "37272E42F9C6CD7E8156C923535EF119"
                                      ++ "B633E896E97C404C6D87565EEA08EB7F"
                                      ++ "F6319FF3E631B6CDD18C53EE92CCEEA0" )
                          ]
    , testVector128 "Set 4, vector#  2"  "0A5DB00356A9FC4FA2F5489BEE4194E7"
                                         "0000000000000000"
                          [ ((0, 63),    "8313F4A86F697AAC985182862E4FC623"
                                      ++ "3511C46B6DAEEDB94B63461111CB4768"
                                      ++ "72F1BC3B4E8EE80A4ADE7D1A8CD49C17"
                                      ++ "1D3A550D3F39B7775734225579B8B60A" )
                      , ((65472, 65535), "6AFA6F539C0F3B0B9DEB0235E7EB2E14"
                                      ++ "B111615D4FBC5BF7FFE75E160DEDA3D9"
                                      ++ "932125469AEC00539ECE8FCF8067CB0F"
                                      ++ "B542C2064267BEA7D9AD6365314D5C2C" )
                      , ((65536, 65599), "296F2B5D22F5C96DA78304F5800E0C87"
                                      ++ "C56BC1BACD7A85D35CFECE17427393E1"
                                      ++ "611975CC040D27DF6A5FABC89ADDE328"
                                      ++ "AE8E9CB4F64CFA0CB38FE525E39BDFE4" )
                    , ((131008, 131071), "86C8139FD7CED7B5432E16911469C7A5"
                                      ++ "6BDD8567E8A8993BA9FA1394348C2283"
                                      ++ "F2DF5F56E207D52A1DA070ABF7B516CF"
                                      ++ "2A03C6CD42D6EA2C217EC02DF8DDCA9C" )
                          ]
    , testVector128 "Set 4, vector#  3"  "0F62B5085BAE0154A7FA4DA0F34699EC"
                                         "0000000000000000"
                          [ ((0, 63),    "62765613D127804ECD0F82D208D70156"
                                      ++ "3B1685EEF67945DAE2900307CDB14EA6"
                                      ++ "2474A439D8BAE8005493455471E7BCB9"
                                      ++ "DB75F0596F3FB47E65B94DC909FDE140" )
                      , ((65472, 65535), "00A0D5B2CE7B95E142D21B57B187C29C"
                                      ++ "19B101CD063196D9B32A3075FB5D54A2"
                                      ++ "0D3CE57CBEC6CA684CB0E5306D5E21E5"
                                      ++ "657F35B8FB419A0251EA5CD94113E23B" )
                      , ((65536, 65599), "AAC2D29404A015047DEFB4F11460958D"
                                      ++ "A989141026FE9325F15954363FC78898"
                                      ++ "D4A20F6870F4D2B124590973F6956096"
                                      ++ "940E2324F7C63384A85BACF53F7755E3" )
                    , ((131008, 131071), "0A543607FE352336ACFEDFE6B74359E0"
                                      ++ "B26B19FD45A8938C6C0A6DB68A137749"
                                      ++ "5B65211558D0CB9ECA9DA2C0E50702B6"
                                      ++ "88B2DEC53AAA2FBF11BD149F4F445696" )
                          ]
    , testVector128 "Set 5, vector#  0"  "00000000000000000000000000000000"
                                         "8000000000000000"
                          [ ((0, 63),    "B66C1E4446DD9557E578E223B0B76801"
                                      ++ "7B23B267BB0234AE4626BF443F219776"
                                      ++ "436FB19FD0E8866FCD0DE9A9538F4A09"
                                      ++ "CA9AC0732E30BCF98E4F13E4B9E201D9" )
                      , ((192, 255), "462920041C5543954D6230C531042B99"
                                      ++ "9A289542FEB3C129C5286E1A4B4CF118"
                                      ++ "7447959785434BEF0D05C6EC8950E469"
                                      ++ "BBA6647571DDD049C72D81AC8B75D027" )
                      , ((256, 319), "DD84E3F631ADDC4450B9813729BD8E7C"
                                      ++ "C8909A1E023EE539F12646CFEC03239A"
                                      ++ "68F3008F171CDAE514D20BCD584DFD44"
                                      ++ "CBF25C05D028E51870729E4087AA025B" )
                    , ((448, 511), "5AC8474899B9E28211CC7137BD0DF290"
                                      ++ "D3E926EB32D8F9C92D0FB1DE4DBE452D"
                                      ++ "E3800E554B348E8A3D1B9C59B9C77B09"
                                      ++ "0B8E3A0BDAC520E97650195846198E9D" )
                          ]
    , testVector128 "Set 5, vector#  9"  "00000000000000000000000000000000"
                                         "0040000000000000"
                          [ ((0, 63),    "1A643637B9A9D868F66237163E2C7D97"
                                      ++ "6CEDC2ED0E18C98916614C6C0D435B44"
                                      ++ "8105B355AE1937A3F718733CE1526231"
                                      ++ "6FA3243A27C9E93D29745C1B4DE6C17B" )
                      , ((192, 255), "CDDB6BD210D7E92FBFDD18B22A03D66C"
                                      ++ "C695A93F34FB033DC14605536EEEA06F"
                                      ++ "FC4F1E4BACFCD6EB9DA65E36C46B26A9"
                                      ++ "3F60EAA9EC43307E2EA5C7A68558C01A" )
                      , ((256, 319), "5FC02B90B39F3E90B8AEC15776F2A94F"
                                      ++ "D8C26B140F798C93E1759957F99C613B"
                                      ++ "8B4177A7B877D80A9B9C76C2B84E21A6"
                                      ++ "DF803F0DB651E1D0C88FB3743A79938F" )
                    , ((448, 511), "B4BC18F7279AC64BB6140A586F45AC96"
                                      ++ "E549C0CA497F59B875C614DE605A8BFF"
                                      ++ "63AB3F1E00DAEAE7A5CC7A7796E9BACC"
                                      ++ "DD469E9100EABCD6E69301EA59C4B76A" )
                          ]
    , testVector128 "Set 5, vector# 18"  "00000000000000000000000000000000"
                                         "0000200000000000"
                          [ ((0, 63),    "94B7B07E184BC24A0904290B2601FC3A"
                                      ++ "C70BEAD7B1FC3294360ED4EF16813453"
                                      ++ "0B4D1F3F28A3C3B248B2E914A8DCBD53"
                                      ++ "26A240C9BB361A8A93D023725BDCD4E3" )
                      , ((192, 255), "27C7A2C4EAA1E2E8798CA71EA50B7E5A"
                                      ++ "CD9FC82263D11781EFC16142CFD21A63"
                                      ++ "4DB2B860B54A9979AFA187CE0667D176"
                                      ++ "23FC91EC1E5E6C31A8089628AC76F9F0" )
                      , ((256, 319), "C2CD243516E5919D6C5C478469260813"
                                      ++ "ABE8E6F54BE8E11D48FEC043CDADA19B"
                                      ++ "EFE9CB0C22A9BB30B98E4CFCF1A55EF1"
                                      ++ "263B209CE15FEAEF8237CFAF7E5286D6" )
                    , ((448, 511), "84489BD680FB11E5CAA0F5535ABA86DC"
                                      ++ "FF30AC031CEFED9897F2528035977726"
                                      ++ "70E1E164FA06A28DD9BAF625B576166A"
                                      ++ "4C4BF4CADD003D5DF2B0E6D9142DD8B3" )
                          ]
    , testVector128 "Set 5, vector# 27"  "00000000000000000000000000000000"
                                         "0000001000000000"
                          [ ((0, 63),    "2E6C8BE7DD335292EE9152641B0E4EFB"
                                      ++ "43D27434E4BE70EAC4CAFAE5C38B2E5B"
                                      ++ "06E70B9966F4EDD9B4C4589E18E61F05"
                                      ++ "B78E7849B6496F33E2FCA3FC8360824C" )
                      , ((192, 255), "1006D6A04165A951C7EE31EEB0F6C32B"
                                      ++ "D0B089683C001942886FCEF9E700D15A"
                                      ++ "DB117652735C546D30177DC14FA68708"
                                      ++ "D591C3254C05B84BF0DCBC3105F06A6F" )
                      , ((256, 319), "2196ADA05BED2BD097A43E4C5BE6C940"
                                      ++ "4A353689939DCB9C4F82278BDB0EB505"
                                      ++ "F70FFD9921B46645EDDFCF47405FD3E6"
                                      ++ "7CAE732B367A0B0F2B57A503161FA5DE" )
                    , ((448, 511), "4A3504DAC25F59489C769090D822E89E"
                                      ++ "1338AC73F22DB2614B43D640525EF996"
                                      ++ "9D6B7E3900ADCBE056AB818E0FF708E3"
                                      ++ "B0A8E63531F252C384DD3DE7318EA866" )
                          ]
    , testVector128 "Set 5, vector# 36"  "00000000000000000000000000000000"
                                         "0000000008000000"
                          [ ((0, 63),    "1D3FD8BAF2A13BCD2A49B50F8DFB0522"
                                      ++ "8E366B4FD2ECD6973DFF116289D7E0AF"
                                      ++ "55EFB875345204B5FCE27A1C6DF79531"
                                      ++ "B3175647526BF5C028C454BADEFBECD6" )
                      , ((192, 255), "F639D0D23CC5817501517216ADA14241"
                                      ++ "D08495F17CDEAFB883CE619A3255EC3F"
                                      ++ "EAADFA224CF354C425A74D3DDAAA0C86"
                                      ++ "E44016238C142B36944EF53A1EC7DF92" )
                      , ((256, 319), "9CAE4D4639696A188E08BC1B01774608"
                                      ++ "5D18418F82DC90742BB6D172414ACC13"
                                      ++ "A4721B018B2CC002CB6E6FFE4A4E252C"
                                      ++ "C4BF5DE975684C8805036F4C76660DC8" )
                    , ((448, 511), "CB2A2CB3136F5CC71FD95A4A242B15E5"
                                      ++ "1C8E3BAE52FEC9C1B591B86DFDDC2442"
                                      ++ "353DF500B2B9868A6C609655FC1A3E03"
                                      ++ "347608D12D3923457EEEB34960F4DB31" )
                          ]
    , testVector128 "Set 5, vector# 45"  "00000000000000000000000000000000"
                                         "0000000000040000"
                          [ ((0, 63),    "2DCAD75F5621A673A471FDE8728FACF6"
                                      ++ "D3146C10A0903DE12FBDCE134CC0F11B"
                                      ++ "2D2ABBDBADFA19303E264011A1B9EFEC"
                                      ++ "AB4DFBC37E3D0F090D6B069505525D3A" )
                      , ((192, 255), "02C401ACF6D160CC1D80E11CB4F3038A"
                                      ++ "4C5B61C995CD94E15D7F95A0A18C49D5"
                                      ++ "DA265F6D88D68A39B55DB3505039D13E"
                                      ++ "AB9DEBD408CE7A79C375FD3FEBEF86C8" )
                      , ((256, 319), "83D92AF769F5BF1FA894613D3DF447EB"
                                      ++ "D461CFFC0CA3A9843E8441EC91DEBC67"
                                      ++ "BE9162EABC5607A6D3FCAD4426EF4F9F"
                                      ++ "3B42CEC8C287C194B2211DEA4549D5D5" )
                    , ((448, 511), "D3F86930112EAFC7AA430444693BAE77"
                                      ++ "3F014D0798CAF3652A3432460F326DA8"
                                      ++ "8E82BE1E08C220B5FCBCE238B982E37D"
                                      ++ "1E60DCBF1747D437D42DB21ADF5EECF2" )
                          ]
    , testVector128 "Set 5, vector# 54"  "00000000000000000000000000000000"
                                         "0000000000000200"
                          [ ((0, 63),    "D8E137C510CDBB1C788677F44F3D3F2E"
                                      ++ "4C19FCEB51E7C2ECBDB175E933F44625"
                                      ++ "C7B0168E446CCCA900B9DB12D53E89E1"
                                      ++ "B917A69BDB888935B3B795D743D0D0E6" )
                      , ((192, 255), "E168F81B5BFB769F3380690D423E251E"
                                      ++ "0F4BEEBE0B02F19AFFADBD94212B8063"
                                      ++ "D77A665FD53F8F1A1CC682599C74F415"
                                      ++ "3642EC7DADA034403A90E1E5DA40C896" )
                      , ((256, 319), "574774CFB8452E82777371616E0AC224"
                                      ++ "E29939E725B99EA8CFB4A9BF459A70D6"
                                      ++ "AB1991E85E06905ACCDA8D1911F82835"
                                      ++ "9C4FD7614A55C1E30171934412D46B3E" )
                    , ((448, 511), "21FE9B1F82E865CC305F04FA2C69EA97"
                                      ++ "6D90A41590A3BD242337D87D28E3041D"
                                      ++ "3D0F74CA24A74453CB679FDFFEE45AA6"
                                      ++ "3B2DDE513D3F9E28E86346D9A4114CD7" )
                          ]
    , testVector128 "Set 5, vector# 63"  "00000000000000000000000000000000"
                                         "0000000000000001"
                          [ ((0, 63),    "42DCF10EA1BCBA82C88DDCDF905C9C78"
                                      ++ "42A78AE57117F09CE51517C0C70063CF"
                                      ++ "1F6BC955EF8806300972BD5FC715B0ED"
                                      ++ "38A111610A81EBA855BB5CD1AEA0D74E" )
                      , ((192, 255), "261E70245994E208CDF3E868A19E26D3"
                                      ++ "B74DBFCB6416DE95E202228F18E56622"
                                      ++ "521759F43A9A71EB5F8F705932B0448B"
                                      ++ "42987CEC39A4DF03E62D2C24501B4BDE" )
                      , ((256, 319), "9E433A4BF223AA0126807E8041179CC4"
                                      ++ "760516D3537109F72124E3534A24EA7D"
                                      ++ "B225C60063190FD57FF8595D60B2A8B4"
                                      ++ "AE37384BB4FCD5B65234EE4FB0A1EBEA" )
                    , ((448, 511), "3F9803DD763449758F008D77C8940F8A"
                                      ++ "FB755833ED080A10513D800BA3A83B1C"
                                      ++ "028A53AED0A65177C58B116E574745D0"
                                      ++ "F28506A9DACD6F8A3D81613E00B12FDB" )
                          ]
    , testVector128 "Set 6, vector#  0"  "0053A6F94C9FF24598EB3E91E4378ADD"
                                         "0D74DB42A91077DE"
                          [ ((0, 63),    "05E1E7BEB697D999656BF37C1B978806"
                                      ++ "735D0B903A6007BD329927EFBE1B0E2A"
                                      ++ "8137C1AE291493AA83A821755BEE0B06"
                                      ++ "CD14855A67E46703EBF8F3114B584CBA" )
                      , ((65472, 65535), "1A70A37B1C9CA11CD3BF988D3EE4612D"
                                      ++ "15F1A08D683FCCC6558ECF2089388B8E"
                                      ++ "555E7619BF82EE71348F4F8D0D2AE464"
                                      ++ "339D66BFC3A003BF229C0FC0AB6AE1C6" )
                      , ((65536, 65599), "4ED220425F7DDB0C843232FB03A7B1C7"
                                      ++ "616A50076FB056D3580DB13D2C295973"
                                      ++ "D289CC335C8BC75DD87F121E85BB9981"
                                      ++ "66C2EF415F3F7A297E9E1BEE767F84E2" )
                    , ((131008, 131071), "E121F8377E5146BFAE5AEC9F422F474F"
                                      ++ "D3E9C685D32744A76D8B307A682FCA1B"
                                      ++ "6BF790B5B51073E114732D3786B985FD"
                                      ++ "4F45162488FEEB04C8F26E27E0F6B5CD" )
                          ]
    , testVector128 "Set 6, vector#  1"  "0558ABFE51A4F74A9DF04396E93C8FE2"
                                         "167DE44BB21980E7"
                          [ ((0, 63),    "EF5236C33EEEC2E337296AB237F99F56"
                                      ++ "A48639744788E128BC05275D4873B9F0"
                                      ++ "FAFDA8FAF24F0A61C2903373F3DE3E45"
                                      ++ "9928CD6F2172EA6CDBE7B0FBF45D3DAD" )
                      , ((65472, 65535), "29412152F2750DC2F951EC969B4E9587"
                                      ++ "DCD2A23DAADCBC20677DDFE89096C883"
                                      ++ "E65721FC8F7BFC2D0D1FD6143D8504CB"
                                      ++ "7340E06FE324CE3445081D3B7B72F3B3" )
                      , ((65536, 65599), "49BFE800381794D264028A2E32D318E7"
                                      ++ "F6FD9B377ED3A12274CE21D40CCEF04D"
                                      ++ "55791AF99849989C21D00E7D4E7B9FF4"
                                      ++ "D46AABC44AED676B5C69CF32BE386205" )
                    , ((131008, 131071), "C3E16260DD666D8D8FBF1529D0E8151A"
                                      ++ "931663D75FA0046132E4AD78D8BE7F8D"
                                      ++ "7F41AAEFDE58BA80B962B8B68762CDF3"
                                      ++ "E4B06E05D73D22CC33F1E1592D5116F4" )
                          ]
    , testVector128 "Set 6, vector#  2"  "0A5DB00356A9FC4FA2F5489BEE4194E7"
                                         "1F86ED54BB2289F0"
                          [ ((0, 63),    "8B354C8F8384D5591EA0FF23E7960472"
                                      ++ "B494D04B2F787FC87B6569CB9021562F"
                                      ++ "F5B1287A4D89FB316B69971E9B861A10"
                                      ++ "9CF9204572E3DE7EAB4991F4C7975427" )
                      , ((65472, 65535), "B8B26382B081B45E135DF7F8C468ACEA"
                                      ++ "56EB33EC38F292E3246F5A90233DDDC1"
                                      ++ "CD977E0996641C3FA4BB42E7438EE04D"
                                      ++ "8C275C57A69EEA872A440FC6EE39DB21" )
                      , ((65536, 65599), "C0BA18C9F84D6A2E10D2CCCC041D736A"
                                      ++ "943592BB626D2832A9A6CCC1005DDB9E"
                                      ++ "A1694370FF15BD486B77629BB363C3B1"
                                      ++ "21811BCCFB18537502712A63061157D8" )
                    , ((131008, 131071), "870355A6A03D4BC9038EA0CB2F4B8006"
                                      ++ "B42D70914FBFF76A80D2567BE8404B03"
                                      ++ "C1124BCE2FD863CE7438A5680D23C5E1"
                                      ++ "F8ED3C8A6DB656BFF7B060B8A8966E09" )
                          ]
    , testVector128 "Set 6, vector#  3"  "0F62B5085BAE0154A7FA4DA0F34699EC"
                                         "288FF65DC42B92F9"
                          [ ((0, 63),    "71DAEE5142D0728B41B6597933EBF467"
                                      ++ "E43279E30978677078941602629CBF68"
                                      ++ "B73D6BD2C95F118D2B3E6EC955DABB6D"
                                      ++ "C61C4143BC9A9B32B99DBE6866166DC0" )
                      , ((65472, 65535), "906258725DDD0323D8E3098CBDAD6B7F"
                                      ++ "941682A4745E4A42B3DC6EDEE565E6D9"
                                      ++ "C65630610CDB14B5F110425F5A6DBF18"
                                      ++ "70856183FA5B91FC177DFA721C5D6BF0" )
                      , ((65536, 65599), "09033D9EBB07648F92858913E220FC52"
                                      ++ "8A10125919C891CCF8051153229B958B"
                                      ++ "A9236CADF56A0F328707F7E9D5F76CCB"
                                      ++ "CAF5E46A7BB9675655A426ED377D660E" )
                    , ((131008, 131071), "F9876CA5B5136805445520CDA425508A"
                                      ++ "E0E36DE975DE381F80E77D951D885801"
                                      ++ "CEB354E4F45A2ED5F51DD61CE0994227"
                                      ++ "7F493452E0768B2624FACA4D9E0F7BE4" )
                          ]
    ]
    where
        testVector128 = testVector $ expand128 $ salsa 20