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
readHex = fst . readBinary . hexToByteString

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

testVector :: (Key key) => String -> Core -> key -> Nounce -> [((Int64, Int64), LBS.ByteString)] -> F.Test
testVector name core key nounce = testGroup name . map testSection
    where
        stream = keystream core key nounce 0
        testSection (section@(from, to), excepted) = testCase ("section " ++ show section) $ actual @=? excepted
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
        testVector128 name key iv = testVector name (salsa 20) (readHex key `asTypeOf` (undefined :: Key128)) (readHex iv) . map (\(a, b) -> (a, fromChunks [hexToByteString b]))
        
eCrypt256 :: F.Test
eCrypt256 = testGroup "eCrypt256"
    [ testVector256 "1 Set, vector#  0"  ("80000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "E3BE8FDD8BECA2E3EA8EF9475B29A6E7"
                                       ++ "003951E1097A5C38D23B7A5FAD9F6844"
                                       ++ "B22C97559E2723C7CBBD3FE4FC8D9A07"
                                       ++ "44652A83E72A9C461876AF4D7EF1A117" )
                           , ((192, 255), "57BE81F47B17D9AE7C4FF15429A73E10"
                                       ++ "ACF250ED3A90A93C711308A74C6216A9"
                                       ++ "ED84CD126DA7F28E8ABF8BB63517E1CA"
                                       ++ "98E712F4FB2E1A6AED9FDC73291FAA17" )
                           , ((256, 319), "958211C4BA2EBD5838C635EDB81F513A"
                                       ++ "91A294E194F1C039AEEC657DCE40AA7E"
                                       ++ "7C0AF57CACEFA40C9F14B71A4B3456A6"
                                       ++ "3E162EC7D8D10B8FFB1810D71001B618" )
                           , ((448, 511), "696AFCFD0CDDCC83C7E77F11A649D79A"
                                       ++ "CDC3354E9635FF137E929933A0BD6F53"
                                       ++ "77EFA105A3A4266B7C0D089D08F1E855"
                                       ++ "CC32B15B93784A36E56A76CC64BC8477" )
                          ]
    , testVector256 "Set 1, vector#  9"  ("00400000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "01F191C3A1F2CC6EBED78095A05E062E"
                                       ++ "1228154AF6BAE80A0E1A61DF2AE15FBC"
                                       ++ "C37286440F66780761413F23B0C2C9E4"
                                       ++ "678C628C5E7FB48C6EC1D82D47117D9F" )
                           , ((192, 255), "86D6F824D58012A14A19858CFE137D76"
                                       ++ "8E77597B96A4285D6B65D88A7F1A8778"
                                       ++ "4BF1A3E44FC9D3525DDC784F5D99BA22"
                                       ++ "2712420181CABAB00C4B91AAEDFF521C" )
                           , ((256, 319), "287A9DB3C4EEDCC96055251B73ED361B"
                                       ++ "A727C2F326EF6944F9449FB7A3DDC396"
                                       ++ "A88D9D0D853FADE365F82789D57F9B40"
                                       ++ "10F963BC498F176A93FD51723FCD4D55" )
                           , ((448, 511), "E0D62E2E3B37FDD906C934FAA35D5E8A"
                                       ++ "89A517DD0F24CF33DE8495C5FF24F4B1"
                                       ++ "476B3E826A1C90D74507C3991CEF4067"
                                       ++ "E316A04B97AEFFA5E9D1F33CB0609B9E" )
                          ]
    , testVector256 "Set 1, vector# 18"  ("00002000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "C29BA0DA9EBEBFACDEBBDD1D16E5F598"
                                       ++ "7E1CB12E9083D437EAAAA4BA0CDC909E"
                                       ++ "53D052AC387D86ACDA8D956BA9E6F654"
                                       ++ "3065F6912A7DF710B4B57F27809BAFE3" )
                           , ((192, 255), "77DE29C19136852CC5DF78B5903CAC7B"
                                       ++ "8C91345350CF97529D90F18055ECB75A"
                                       ++ "C86A922B2BD3BD1DE3E2FB6DF9153166"
                                       ++ "09BDBAB298B37EA0C5ECD917788E2216" )
                           , ((256, 319), "1985A31AA8484383B885418C78210D0E"
                                       ++ "84CBC7070A2ED22DCAAC6A739EAD5881"
                                       ++ "8E5F7755BE3BF0723A27DC69612F18DC"
                                       ++ "8BF9709077D22B78A365CE6131744651" )
                           , ((448, 511), "9618FCA736A8ECA00BD1194FC9855085"
                                       ++ "526ECD47A8DE1F8DB298AD49FCE935EA"
                                       ++ "63B548597092ABAD6338F41AF87586A7"
                                       ++ "0505F2537902B81F55E53599DABA84CC" )
                          ]
    , testVector256 "Set 1, vector# 27"  ("00000010000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "FF852567EB72687DC56C122D61B2FB2A"
                                       ++ "4FB9E8E8DA62313B618D10F8E0DA521B"
                                       ++ "176E879CD78E641043F0FA4A22211566"
                                       ++ "429B7C68EC645FF5E44B2505D61A2D71" )
                           , ((192, 255), "E5B040B199C3DFC8DB1F41C74C798AE2"
                                       ++ "62105477AEB1CE761D6FFF1CAB15AA1A"
                                       ++ "7B7CE26B9CCE6DC33FD4522BF8F73E70"
                                       ++ "B843D67FC06FA2258F9709DB14FBD54C" )
                           , ((256, 319), "55706075E5FED81E2205994609868EFC"
                                       ++ "383B3E4CC295C4214356BA41FC72BFE5"
                                       ++ "4E6936FE6684EAF93C5973DDCD8E8F23"
                                       ++ "767B82D783953F89AF4E808C90BEEABD" )
                           , ((448, 511), "7ECE71883742EE852C94F01AD85EA1A6"
                                       ++ "76CC7CBC6EDFCF1BAE751455A923FAAC"
                                       ++ "806BB72E6A982EC7A38F112445E25EB6"
                                       ++ "BC5B49C5E6C22DC8748DEE0942F6E8B2" )
                          ]
    , testVector256 "Set 1, vector# 36"  ("00000000080000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "AF6E2EE1D5021675A92F02C764AFD94A"
                                       ++ "F3097F53532FC965EB861D6D12A3A012"
                                       ++ "ABA683A5281238CE76E3AF3944736752"
                                       ++ "AD86A5FD16E7DAFAF241ECFB0ADBBDFE" )
                           , ((192, 255), "19444E6D7C3D8BEC0957C3E785E1EEFD"
                                       ++ "56B857F21CF8D325A4285F8DEF5078FF"
                                       ++ "7B7EFB5E3B20F6E0906265B6F7580A04"
                                       ++ "9CEC5DF1872DCCB54081054C0FC15514" )
                           , ((256, 319), "7EB544ADBF57D042E3A6753B13C65843"
                                       ++ "0399764CF90D007E48DAFE3DA1FE3F90"
                                       ++ "8EF4BFA6AF96DCD54197DA0D3A10FA35"
                                       ++ "6A374DA08B9A84044E70EC70ED050D46" )
                           , ((448, 511), "57224DA912C62801DB393D5E3F4EDFF7"
                                       ++ "D61BA895F88C7391FE5C943B88CC4642"
                                       ++ "0D11C3F1884B628F03C04A3C10F03FFB"
                                       ++ "CFC652D066BFD8DBF52DA2A72B9B9AC5" )
                          ]
    , testVector256 "Set 1, vector# 45"  ("00000000000400000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "D203CC523351942C94E215F6D5CC1425"
                                       ++ "C5FFB2EA9A916C0D4F7B343333A58D94"
                                       ++ "1DE20B5F543E3EE63C29D981469ACE48"
                                       ++ "86ED9DEF839D4FBD20CDF9D001F1B89B" )
                           , ((192, 255), "9E37D2BE6473F4FA87ED294765816BB0"
                                       ++ "8CCA625418155F6704CB48082A860581"
                                       ++ "A9CF69D9145D0DCB2621E1515013DD3E"
                                       ++ "18819BEC5C186628ED545BFF7E4AC1C2" )
                           , ((256, 319), "B8648B92B5A7B3B991722F0053909A3F"
                                       ++ "052E8F7DABE7FE0E34498C1C550DE9D5"
                                       ++ "3CE0818DDBA82F0616B3F79AD72B0BF9"
                                       ++ "B5FA2F2B8032B1860FAB0804934FBD00" )
                           , ((448, 511), "0CD554D10A975BEA79AEAC663F5FF984"
                                       ++ "15883EB558925C5ECFA53D77FAB4B884"
                                       ++ "FE4D705B1E1B34A938C1C2D8528E1FAB"
                                       ++ "4C9A7512F12707B78F2B6BFEE8D76E57" )
                          ]
    , testVector256 "Set 1, vector# 54"  ("00000000000002000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "C45E28A2C9A80AC07A760580DCD96340"
                                       ++ "26651B25BA2332FDAFC9AA16998317B9"
                                       ++ "751A446302CDE95525C709E79CB55951"
                                       ++ "4E4A54FD73ADAAF0AB3A3F1ADDABBADA" )
                           , ((192, 255), "17937670127CBF691AFDAD6D36994F0A"
                                       ++ "40B3F369C21691B887CFE20B0F63D125"
                                       ++ "8896C88CAB669ED6FABE464A700DA937"
                                       ++ "C43AABB45E60F14E6EBA69FBC9F2FCF3" )
                           , ((256, 319), "2690AB8F4616302C49D79CFE3AE29AA7"
                                       ++ "9C4D1036E0CBB1D24C4682BCA0E1C1A5"
                                       ++ "80904001185286AC3C63BFBF909F4A36"
                                       ++ "525D2A732D7D166A52E087444DE24469" )
                           , ((448, 511), "9E5E91D8BE1E46B0BAD46ED9ACCD440A"
                                       ++ "01882556B51C2B7CCC987A6C554201FC"
                                       ++ "6CE8DA0B1CD42C011A085EB8FBA0F8F2"
                                       ++ "623B6B9627EAEB91C05CFA3090A28040" )
                          ]
    , testVector256 "Set 1, vector# 63"  ("00000000000000010000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "5F7B6B86B0C197B960D8250B5106CFEB"
                                       ++ "F6F4DE0D94D3958945FA979534AFE19C"
                                       ++ "D5305C55A1404C59302F05ACC819D3A3"
                                       ++ "B0BDB9D154A45C0DEE52F25012DAA445" )
                           , ((192, 255), "20F99149AA74F631D22BEA8D85EC84A6"
                                       ++ "57C2E8703B45ED36458F0ED47408C3C7"
                                       ++ "E6624A184E7CED17C93CBC9960914A61"
                                       ++ "E71083308CB7A55D7723C2B9E6A2F087" )
                           , ((256, 319), "EBB0F7194EA7AE5D28B916D361B19394"
                                       ++ "A163A6EB124D37A372A798135E4F2FDF"
                                       ++ "2EF422997F5AA1F9DFA3B1826431AA62"
                                       ++ "99E0AEB44D844E297604D27974EAAD6B" )
                           , ((448, 511), "65CA9CAE36B65F58085D561A91CFDBE1"
                                       ++ "EA0400CDEB4AA1B987FAC06702590D8B"
                                       ++ "39B6228E6F4B81BB91852971DE2D3436"
                                       ++ "C8C24FA193BC10BFC5534BF5915A245B" )
                          ]
    , testVector256 "Set 1, vector# 72"  ("00000000000000000080000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "B96FCF5A182789AD14E53FB2E981E496"
                                       ++ "B47C6B44BE7EF95692F19AE24E193219"
                                       ++ "6E180778AC04A0EB2497497680587FEB"
                                       ++ "F412BB3A67E9538CA5B2A373E16E60F3" )
                           , ((192, 255), "953544577886B26F2F8D7BD237D7AE8E"
                                       ++ "5D425523F6180C9591206E10E166C7E3"
                                       ++ "06537355EFD9C32FF1C8808537BA12D5"
                                       ++ "B0E303DBCEC7DB3DA6E3A16DACB1E7FB" )
                           , ((256, 319), "9B416AA89BDC5589A1C9046D2D308B8A"
                                       ++ "CA852008C6503B373250C2639C693D9E"
                                       ++ "164FC0E94FCFBB35D67D45DE1A3D838F"
                                       ++ "302915E78470EB47654B87540AADF90A" )
                           , ((448, 511), "3911737593809A1A9FD14F57950AEFCA"
                                       ++ "66E1E45475D39335DC01FFA72E431A85"
                                       ++ "01E146994FAA64BA37AF255F1951B33F"
                                       ++ "CB28AAC76BB08AA0917B53B9ED64CDAD" )
                          ]
    , testVector256 "Set 1, vector# 81"  ("00000000000000000000400000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "2B08D82E92AC352247211D5F0791DAC9"
                                       ++ "D585ABF67DADFBD7B5AC60EB2EEF4C72"
                                       ++ "F6F71CA110DEE4CB2F19FABE4F442B2F"
                                       ++ "5F9FB1C94FBD553C21CD5B0CEF139880" )
                           , ((192, 255), "AAD0055BF85562F06118CB260CB0BD5F"
                                       ++ "374CD798021593F03A67134EA8A73B22"
                                       ++ "F00F09BAB770D1287FFF17CCF5F1CF32"
                                       ++ "86833B57F4397B16A9F8351922042810" )
                           , ((256, 319), "724D557F9D7DA4AFCB5DC6D1040DD8BF"
                                       ++ "A14A0CC61F7206606BC99385D15BFED8"
                                       ++ "9C4D69EFE5711A9E256C908AFF2734D6"
                                       ++ "501C9D1AEB7CCD1029413BF7FA40848C" )
                           , ((448, 511), "8960F4D83E21984B3A6D5D1B667944ED"
                                       ++ "12814CD390B107A502A4BBA620E3CE9F"
                                       ++ "6DAF2D4629C828C59E86F09F1F435B4D"
                                       ++ "40A1595C3D5B6E0744FFA546B22EF865" )
                          ]
    , testVector256 "Set 1, vector# 90"  ("00000000000000000000002000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "C9969A75572ABFAA28FBE769A287A676"
                                       ++ "3B534AF50B697C31B7F4CD8F50DDF2F2"
                                       ++ "17B3C5532E95F73AF11B0693D5A33A34"
                                       ++ "DAFBB64635A195EC9477FDFD69AE7540" )
                           , ((192, 255), "6B358B53A60B9542F582FDE14B2711F2"
                                       ++ "6CD1B7421B4D872B95E347CDD7D763C8"
                                       ++ "73C2A8730A802AECA326FD63C8C4205C"
                                       ++ "FC1A6E2F4DF7A6ACF1E22A2BCA5379A9" )
                           , ((256, 319), "AF64A04DB6B9CA63429E0D81CE975FD0"
                                       ++ "2A5E3BB8C1A0C3D35636AE22F3733201"
                                       ++ "2DF59549BAC23E992A1E4DD481F91956"
                                       ++ "40C4D6EE0E083702DB18328D42D93BF7" )
                           , ((448, 511), "3F3FD5559C9C0CE3B5B484BD15E75CAB"
                                       ++ "B252CC44961C1ACA86B1722FCF205408"
                                       ++ "EF9841F947224170ECAC6503F7A8FEAE"
                                       ++ "7281ED1D9A18C4C00D12C8E40F21876F" )
                          ]
    , testVector256 "Set 1, vector# 99"  ("00000000000000000000000010000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "698BFC90B147715FB9F0CA1DDC94EE10"
                                       ++ "3082316701CDD1DF2EAE752BA485F585"
                                       ++ "9E131D0D9233B16890BD5946CBCF116D"
                                       ++ "B50E8E2DCAE104162C7B76CB3D11445C" )
                           , ((192, 255), "07D49AB7BA8451A2A68DF473C6D1E91D"
                                       ++ "407038568FADA2DB948ABFBBE408401F"
                                       ++ "DF5960241325F2981DC17EAF1C333CDC"
                                       ++ "91E27EC064734234656AED7A944AD78A" )
                           , ((256, 319), "C152FCF951DAECBD48EC1D0122A4EA00"
                                       ++ "9FB8FD03E35E283109DAA4E033783990"
                                       ++ "DADE92932BC6410CE1B6ADE414AAF782"
                                       ++ "8DA024FB2C3F4135DF6C42A347BD3E25" )
                           , ((448, 511), "BD0CD02750FE445A0C03D2EA30D73684"
                                       ++ "07DF4B13CBE8E3CE2DE2780F9A90983B"
                                       ++ "9EB919DEF1EC22EBEE10F584B6FE8F99"
                                       ++ "1374666D378C7C20CB5AD1771FA7C799" )
                          ]
    , testVector256 "Set 1, vector#108"  ("00000000000000000000000000080000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "07AE6801D7A94836ED52CCD69D9E97F6"
                                       ++ "34B136A234B978BAE4302F475B0A6B0E"
                                       ++ "A7905CEE090F648962BB969CB4D65228"
                                       ++ "03E1ACD1DCBEFC2E7482C0D426E4BD95" )
                           , ((192, 255), "145DF9D539C59467F55E67D959FC8C8B"
                                       ++ "2CB0397F64D6F122C3F2F1A19E0D67B6"
                                       ++ "9696EADDC6DDA6E80D5A0C0AC1F555A9"
                                       ++ "21C054E0E75EBB246C8E20A854A38E93" )
                           , ((256, 319), "2BF710E9709B5178E5E50B421BAAF59E"
                                       ++ "B1F267F41C60E9E91695D658BAD32497"
                                       ++ "B56868B8738BAA6A15BDE89D69900ED2"
                                       ++ "742F26285504C3D4748F77EECC0D4A67" )
                           , ((448, 511), "E93A249CE755F099C81FA40B5DA6256E"
                                       ++ "E185FA1EFC475EB404BB68C13A921FA5"
                                       ++ "78785537DD65964B9BF77F68DBAE4926"
                                       ++ "9F5061B19AF08B82C372AC69EB64D762" )
                          ]
    , testVector256 "Set 1, vector#117"  ("00000000000000000000000000000400"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "A374C1F86586B0D5A121E1F734EE70CC"
                                       ++ "7072284B322BF61F88336EBE84B53219"
                                       ++ "F4D1FEE2C5EECC4A421BA8AEA9D108E7"
                                       ++ "21A7A82DD979F2559BB0E45CC88C8780" )
                           , ((192, 255), "B0CA15C769D66B26CA4A6D4772AE3521"
                                       ++ "AEA4696890998954F33ACA8638FA50E2"
                                       ++ "9981C2F84596D9371644D18E3EB267E8"
                                       ++ "FCCC98D95A2FB38639D32468A3013B5F" )
                           , ((256, 319), "1CC3AE9293EE9CA19C12D9ABD7000F99"
                                       ++ "047B86A868E82A839DD95418EECB23CB"
                                       ++ "4B4A08E3EF69CC639DBADF3F5F33FAD5"
                                       ++ "0762C2603DFC48882EE8D2346FDB426B" )
                           , ((448, 511), "0D6EC570BB04230AC35B49A1271336CA"
                                       ++ "721E0395F63D306554158154CA12FB62"
                                       ++ "E8D45CF5E21A311554DE9DF5D90CA99E"
                                       ++ "9B7FAFEFAD3597B50A17FEEDD9966884" )
                          ]
    , testVector256 "Set 1, vector#126"  ("00000000000000000000000000000002"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "19F23D5CB3C7303D56AFF18413835EF3"
                                       ++ "DF7405C30BE5F19C72FE8746BA04610D"
                                       ++ "D5D261FB3A0E8C11D2478F4A4D6CF820"
                                       ++ "9730187BB1386C03229F4EB02C5B4422" )
                           , ((192, 255), "7B814D9DB8DC9C8397C23550DE194BE2"
                                       ++ "74694399A8B2BEF6B8095704C2A29E00"
                                       ++ "DEED66C8191F67BA9C048CA41DA4DB05"
                                       ++ "FDEAECBBD0727AD9664563991A22EA46" )
                           , ((256, 319), "7B4DC904BA9FC0CBB054FB57DAE11C58"
                                       ++ "C9505A98E319B43FBB9C30DA2CA7E6B8"
                                       ++ "7A42F1E40774A6657EB3EB2C33B5D365"
                                       ++ "BB92A8CA0CCD5B71C17F7022DD840E14" )
                           , ((448, 511), "5B2DB8E73DB53C289E8479F524953BAF"
                                       ++ "D881E8A366899440175CB2B93F8EBF25"
                                       ++ "3911652B3C7EA35B41B409B4BBD0BD93"
                                       ++ "95AE5A2AE2368B7A43A0F9844239E3C2" )
                          ]
    , testVector256 "Set 1, vector#135"  ("00000000000000000000000000000000"
                                       ++ "01000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "B18CFBA23F81884FBFEA037648B1715C"
                                       ++ "EFAEF1D8CD5C98957353E82B838FE332"
                                       ++ "672B3D7C2905979698F6F6D98EAAE8F9"
                                       ++ "8DA16EF393CB150228FE6438440C5759" )
                           , ((192, 255), "BF285CEEEE6D66ED9A401AF86B4F1B0E"
                                       ++ "69B5ABF625D0C35220F9E6198FF5C225"
                                       ++ "A728EEBF67EDC8690ADFB6A2E43ED7BD"
                                       ++ "2956A4915A8FF4BC584C803C87B03956" )
                           , ((256, 319), "0FBE7818D981B60177DD1C7ED21FC23F"
                                       ++ "F088EEB3A36A3DB18E37BAA312642BE6"
                                       ++ "481F6FBD4C6A3DCF6990D3F5E0F02813"
                                       ++ "F66F42B4384F3821E9F2A5CC7AC37029" )
                           , ((448, 511), "A72F53B68BF3E6972515790869B97667"
                                       ++ "E353E1CC089AFA194B8ACFCC4C033567"
                                       ++ "4B2E9E0290501D24D87B80AF12C636B9"
                                       ++ "3902F09252F77812802151798FDB831D" )
                          ]
    , testVector256 "Set 1, vector#144"  ("00000000000000000000000000000000"
                                       ++ "00008000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "0EEF3E17B6B9388FB55C2C0AEF9716CB"
                                       ++ "106786EEB0E606E124C41AB552EF3389"
                                       ++ "7902AA2AE93D9E4628E785B356C53AC9"
                                       ++ "70BDEE2A7DDBAB427371903EF3EC9FA5" )
                           , ((192, 255), "BA437BE85A1152B673AB7F39345534C2"
                                       ++ "6B53227FC8E99B6EEBCBBDC00B436DBD"
                                       ++ "E6AEF836EC78AC581F251D0C61F56404"
                                       ++ "D275B1DF39294B26CF24F4AC0792D176" )
                           , ((256, 319), "381C3C583CFB20763CDBE072668FD1A2"
                                       ++ "557A35901CDC8595393181AF1610300E"
                                       ++ "D751154C050D8CE0354EFD30D05251A9"
                                       ++ "7F215A48F8924B4A68FD475C793A0543" )
                           , ((448, 511), "15E30D96D2A42C99DB1030B5280A6313"
                                       ++ "2AA665B57DEB3AC6AAC8DDC1450C899B"
                                       ++ "D0DAE783A224134232687459917CC525"
                                       ++ "6D76929A153950DBFF7D12CA21EE77C9" )
                          ]
    , testVector256 "Set 1, vector#153"  ("00000000000000000000000000000000"
                                       ++ "00000040000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "AE5572D5E61A992162AEEE513815339C"
                                       ++ "93A994DB12576D087EA4A9A98EA5946C"
                                       ++ "F58794B43515A4B55C5E9B28A882DADE"
                                       ++ "7D3BFE82B32EC3B604D2C1E1B37B1B99" )
                           , ((192, 255), "247616FFD99152BBFA71D2225AB667DD"
                                       ++ "1999ED6E2AC64F60F43B3DD1EA5E574A"
                                       ++ "47C52B82E3FBA3443996EB1E842D11EF"
                                       ++ "78572638CA556157674B0A38ADF26F8C" )
                           , ((256, 319), "1BE7BBE4FA4078886183F1DC9E296911"
                                       ++ "96106D005F5D653AAE744B2506401723"
                                       ++ "30F38DA7C5CA81F38A879D79FAED5B23"
                                       ++ "37045434875074B65D7E126DAF8B728F" )
                           , ((448, 511), "89048CF63BC3AC13B4637487735B9976"
                                       ++ "2707C4161EBD6788289F2BAE38D3B68D"
                                       ++ "14C9A49E26573E3604D8D9907D151C75"
                                       ++ "6728F3D9A2A6BC118E62390BC0DBACA9" )
                          ]
    , testVector256 "Set 1, vector#162"  ("00000000000000000000000000000000"
                                       ++ "00000000200000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "BA66E5BA75AD8C4030AE54B554E07A97"
                                       ++ "29685FDF033CCC35A153334E9FC93A90"
                                       ++ "3C79F281907BADF6F37123819ACA25E1"
                                       ++ "F03BA0AC69D9B2D5E447F59F31A7A402" )
                           , ((192, 255), "6B0FC33710282B08A33917D23186B1CE"
                                       ++ "0964104B5B8FC229CFD79BAEFF04FF97"
                                       ++ "07AD12904B3673B15B72428BB3FDC0FD"
                                       ++ "DECFF9AF8606456774B1B3B53AE74C5F" )
                           , ((256, 319), "FFD0D5ECE17F9C1890199A4F201333F3"
                                       ++ "D55A0AE07B1DBC50A704FE66493B71AC"
                                       ++ "F802534FCD7BAF86B140CF87C582BC02"
                                       ++ "59EFE52CB2D1A64524F948A86F756E21" )
                           , ((448, 511), "81EF72B6DD7F8043A078486BF0DFA634"
                                       ++ "7CF53FF6432432B45CC740533243D6E8"
                                       ++ "E936A5E6C1CB688388D6D97BFE48C430"
                                       ++ "0325A4B5DE69825E6CB5409FE9518708" )
                          ]
    , testVector256 "Set 1, vector#171"  ("00000000000000000000000000000000"
                                       ++ "00000000001000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "59DBEE08FB86EBCBEBFFBF087F9DD881"
                                       ++ "2AFFFD75414B5162B5E7AE540BFA8777"
                                       ++ "5BEC4982E1F4B6985DC8B2B25F061947"
                                       ++ "61BD6BC5EFD66B2A1EB12833733E5490" )
                           , ((192, 255), "C54CDD55BBBC09038A772D1FEE876EF1"
                                       ++ "88110319FD6D7B306E9F5ACBF3C47824"
                                       ++ "9E4CD2C8C11900DBAA39F8F7D57724E3"
                                       ++ "70606016AFC49DEF5248964A416E0DC8" )
                           , ((256, 319), "EE1C6E2F9DA5404012821C3DBE703D47"
                                       ++ "1FF717042C20DDB4743246448F431DE1"
                                       ++ "53BADF69A059D161189D20B8F22F1F7C"
                                       ++ "C491B5B2F5CDFE7A779A0F9DB0C60586" )
                           , ((448, 511), "85E92E3EA90E7EB79A9D3894D0B21153"
                                       ++ "DA80FCC6DA7631A1C38EB38C78A1BEF2"
                                       ++ "321265349CB5FCFA22E5FD02648BB37E"
                                       ++ "74D3152011F7640A0FD42DCC9457B2AC" )
                          ]
    , testVector256 "Set 1, vector#180"  ("00000000000000000000000000000000"
                                       ++ "00000000000008000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "FD1D039AE6D953654A63334A92CEC647"
                                       ++ "A671CAB6374DB63B89DA1A12B99C231D"
                                       ++ "C7B9418D44210CB0C88F114EAA54AE4A"
                                       ++ "096FEFCCBF51062E8EFD169715677F28" )
                           , ((192, 255), "119152E46B97338C5E50A28DB78757E6"
                                       ++ "B21C9C03AA9D96B5FDAC9D352AADF2F9"
                                       ++ "FA0FCA07649582E7288297E9CC765846"
                                       ++ "2D929ACED1F14E3AEE634CD2086D1762" )
                           , ((256, 319), "F9C91CA01A70253BC6D88A8DFA00537C"
                                       ++ "E635634769E8867B279C1A052A921F14"
                                       ++ "8810FC8854BDF58F99E36FEDBC6E6E6F"
                                       ++ "78BC8F82DCD18D408B3B4F8BFEF12F12" )
                           , ((448, 511), "C22A3D49E727785EA32E83E79E349D62"
                                       ++ "C2647AC6D531BA2D466CCD7CF29D04D1"
                                       ++ "015D41A79C9BE4B0AE1844DBDBCD7FE6"
                                       ++ "765EB95A0D5E121F48840937AB399C6E" )
                          ]
    , testVector256 "Set 1, vector#189"  ("00000000000000000000000000000000"
                                       ++ "00000000000000040000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "72491EC81A704E3694C83FCCC47CF5E8"
                                       ++ "7B66F7B7979F78D8150A606ACDCB4492"
                                       ++ "F64A9D7D9DAD5042F8738DB462F4728C"
                                       ++ "2475F5FDEE985CD3601FA31F576712C3" )
                           , ((192, 255), "17566EFAC19AFD1ADDEC66F42695006C"
                                       ++ "EDFBA525E8F41DB02BE50D2AC4CB497E"
                                       ++ "A10C6DA38ACF39BB608F40AD854F69C4"
                                       ++ "4A0FC6696F6FA8361CF26D5411B1C7C9" )
                           , ((256, 319), "E3CE396F970BC54C9E46B6129B48616D"
                                       ++ "F7FBD0293B1EFEB772D99CA90BCE12A4"
                                       ++ "AF729DA0B94223A3D2F0B9605DC04BF9"
                                       ++ "AE82E065C1B963039802BE6354D3EB2C" )
                           , ((448, 511), "C0B2081FF9B7F2DDD59EE6808F6181F0"
                                       ++ "4CD19D4B0D3F032D5FC0EA2B81D49276"
                                       ++ "BD6E540648576CEAE720411523889D3C"
                                       ++ "F14BF05DA43D8D6155B7D98B021F269E" )
                          ]
    , testVector256 "Set 1, vector#198"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000200000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "E3D058FC000427B4F0802300E5D7FE9F"
                                       ++ "8E3F68E9E8339E9F4C5DE62252E14857"
                                       ++ "71371DE4D2E1C97DC4172AA378924AB4"
                                       ++ "2CADF887136B88D6FEB6514538EBA847" )
                           , ((192, 255), "80CE800DC11805A7522E3B423699D68B"
                                       ++ "51BCCE201ECA4F8E465C5A58A558A71F"
                                       ++ "019A22593CBC148A76647A527E635A23"
                                       ++ "4096EB22F081F39B5A9DC7649277726B" )
                           , ((256, 319), "30A91E7D2CDB7D1B080750B433A14F7B"
                                       ++ "6EE602EB53D67AC65B7E4219B533AA6C"
                                       ++ "CBC1FCAC070270D595CF9E90FD3C2D02"
                                       ++ "A707F7C1F97059DB3644F50D236933B0" )
                           , ((448, 511), "79FA6D08B8DF687EFE868E67643CB5A9"
                                       ++ "FC5FECEEC258E67D831D20AD3C8CBECB"
                                       ++ "51F1712A0BAE64202FBF66A1FAE767C1"
                                       ++ "68A9B0C4BE89FCF2F6D2DBC5CA96A4BB" )
                          ]
    , testVector256 "Set 1, vector#207"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000001000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "FF0D93064CDBD91A8D6BD0B9267A4F93"
                                       ++ "DF7D3C76BAA5D0D14798812203C55A34"
                                       ++ "3BD50E6931394DAB88F514F44E2A1FB5"
                                       ++ "8EF3A915F3B60DAB35E36174AD92B3B1" )
                           , ((192, 255), "074A711F8BB92EA6953D21F9FD7AAEA9"
                                       ++ "1C12D18A2B18E8D325DB04029B5E8EBA"
                                       ++ "43C408D3D4EBE049440CFB716BC3ECA9"
                                       ++ "1929E009ED7EA0EA7273E32C13F44346" )
                           , ((256, 319), "6BD5DE42827A81941C72012219EED591"
                                       ++ "BE1AFE19DF91C8B7284DF2AF4050D7EB"
                                       ++ "674DBE78680EF4F8963D59ACB05B43D6"
                                       ++ "A52B7CEBEBDED9D3268D0500699A036F" )
                           , ((448, 511), "9748C1BA603FE3DD4435A25F2ABF18B4"
                                       ++ "9F25ECEBC3514785406425E03ACD369A"
                                       ++ "EC91463FDD5F3611F06870D513B10DB7"
                                       ++ "730F3328C22312DE7329DF8CB43DA5C2" )
                          ]
    , testVector256 "Set 1, vector#216"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000008000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "DCC597DC08E1AD1451E69D857AF803BB"
                                       ++ "DBF7CD6D510D5C59C9D6C66EB153CC79"
                                       ++ "F9A6228ADEE570983E959788628F174E"
                                       ++ "5833B5CFA350C0C2D8A18F7FE46BB4E1" )
                           , ((192, 255), "8CCB839CB382DB591B5C80F6DD7EAE7E"
                                       ++ "AECB3C8BF29C9C6074058A5EA04E2E58"
                                       ++ "675B4537B8FD061BA7E4195AD2A3EC29"
                                       ++ "FD260FD19F0AAB3DCB7BD483ED8FB860" )
                           , ((256, 319), "73E92E3449C863E55E9A41B0DB35805F"
                                       ++ "344FB07E4C3CEFF25B261819140C849B"
                                       ++ "E90639644C542880946582842CE5B1D9"
                                       ++ "FA2DF07B5589C8C68BED84E15DED4AF2" )
                           , ((448, 511), "693C7F397D23C831431264E9BF4EE963"
                                       ++ "B8A43C6ED939B324FCB8AF1032BAC678"
                                       ++ "C71F1DE8BA3A8090948872FA9C747AB7"
                                       ++ "67F7D162FD8B6F484B81AA54151612A6" )
                          ]
    , testVector256 "Set 1, vector#225"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000040000000")
                                          "0000000000000000"
                           [ ((0, 63),    "C94A72C1B17F8B9F26420BF06B3A5445"
                                       ++ "20C658D5F77ED7D62CC65AF824BD5678"
                                       ++ "98EE4928AF0E2BEDEA64D5A7C22749C3"
                                       ++ "C16369D274EFD2A6DF2CFCCB130A1144" )
                           , ((192, 255), "2130A7225D4C78BBBB8C5122C18851A9"
                                       ++ "32A78E360E62E56058027C624DA49EEC"
                                       ++ "34DCE5ED9F66D78B44334CE0E3317AFF"
                                       ++ "5BC78261FA4C96A642E846CDCEA4C242" )
                           , ((256, 319), "575EAB318220A54E5B2B0A8EC7F54429"
                                       ++ "0719FE422C646E1114D807201416F37E"
                                       ++ "B5CECDB278AFC7CDE84E6DB5CA164840"
                                       ++ "2BF9654D1C4E96A3E7BF5C19C84CDA71" )
                           , ((448, 511), "EAFC6C17BF190180FFD817644D7933C2"
                                       ++ "F86989ADF705A72B04CDF8227A164596"
                                       ++ "7BADE4A0E706039BD84702395B9A44DC"
                                       ++ "7368E198B01335577A28028FE2F6056D" )
                          ]
    , testVector256 "Set 1, vector#234"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000200000")
                                          "0000000000000000"
                           [ ((0, 63),    "832A824C044E27605AD9A3201EF106C1"
                                       ++ "A19B6FC6EA5B328DC1D1FC59086C498D"
                                       ++ "47E7568CFA9616D7D5E63D9C087CC426"
                                       ++ "B4276752E0FF14D7F1E258F9A28A54BA" )
                           , ((192, 255), "CFC021E1EDACD733768D3412C0DA7177"
                                       ++ "7AF74D147D075BD5497BAD89B84D0A66"
                                       ++ "F7F4D0E46B77510AE3FB57C0DB9F9922"
                                       ++ "111337BDFF89A9169DB16B38F305BEC8" )
                           , ((256, 319), "CE311109342E1A41ADA17363B0AB030D"
                                       ++ "1BE9C62F15C2A5D8FEE2BC9819F2E064"
                                       ++ "6880D350E547824BDDFD5BE89C43F23D"
                                       ++ "FFA366BE34629F6EE929E2701EFA6829" )
                           , ((448, 511), "DCE864E5E336A7B51A7FFE9E4C8C1FBE"
                                       ++ "F5F4755A0877EE91D61D1F20F29485FA"
                                       ++ "A879323F2566590917417C4AC0076CB9"
                                       ++ "81EE78C58741506F725BC58743957CAC" )
                          ]
    , testVector256 "Set 1, vector#243"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000001000")
                                          "0000000000000000"
                           [ ((0, 63),    "28DD9E566F018FDA0251E1E648057E85"
                                       ++ "211831E215AE21525E04C932736245C2"
                                       ++ "288AD4A197E4ECA04003B85C3B80D02A"
                                       ++ "9B82C28E7662A34467946A34257D8D0B" )
                           , ((192, 255), "DDC4A6A1AAF92AB32D2958DE67BBA593"
                                       ++ "338D7EE4E3A412C2374A5D63E6CD7F56"
                                       ++ "51F518251CEEFE1E63636DB2F432F407"
                                       ++ "88D4C0163738446515A62637695D782E" )
                           , ((256, 319), "107AAEEDD6C459411921177468E3D013"
                                       ++ "50C40AEB41EE50AE196754BBCE5559B9"
                                       ++ "7276957DC73141981DC087209378F87F"
                                       ++ "89C8423ACE0EAE8C5EFEEDEBCBB20618" )
                           , ((448, 511), "A3FE61185B31AA80EA384B36CEC7F41F"
                                       ++ "19F2E55614BE22852E796963326B9F49"
                                       ++ "72E8A316D4A6653CCE3FE06014C0F5BB"
                                       ++ "6E4E64B439109608FEC6A44C15384C13" )
                          ]
    , testVector256 "Set 1, vector#252"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000008")
                                          "0000000000000000"
                           [ ((0, 63),    "E48C2F264BF9E8374B78FB652BAFF1E3"
                                       ++ "3ECB4B1C635D76A64ECFC4BDE00EE5C8"
                                       ++ "77E1094D6480CA382815CCCD5CC36770"
                                       ++ "46E801C29A860EB032420DCAEEBC36F4" )
                           , ((192, 255), "D2EEE83D63F96B0B7E6D8E0C72B6581D"
                                       ++ "50AF4081017CD62A73789C8C2DC5483F"
                                       ++ "CB4067C71FDBFD6EA8882FFBAC63BC9C"
                                       ++ "5E4F438A2ECBC71627646539A5BFE1DD" )
                           , ((256, 319), "BDDA0B90B24A4FF5D535E12D075DCE84"
                                       ++ "6D6741F809D105DC03552A3F13AC88B2"
                                       ++ "F98411A1C19CB32FA3F595CDD8F87608"
                                       ++ "3C057E42BDD903A055F13182CA080F4D" )
                           , ((448, 511), "44E931EF73A9AFA565EB9A8E6AB1AA3B"
                                       ++ "9F14FC198B41909CB31B532F9EB776FA"
                                       ++ "B51FFD895E7F266D1D275463282BD7F6"
                                       ++ "62FBBBB5629890A4C68B6F6CF8200623" )
                          ]
    , testVector256 "Set 2, vector#  0"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000000"
                           [ ((0, 63),    "9A97F65B9B4C721B960A672145FCA8D4"
                                       ++ "E32E67F9111EA979CE9C4826806AEEE6"
                                       ++ "3DE9C0DA2BD7F91EBCB2639BF989C625"
                                       ++ "1B29BF38D39A9BDCE7C55F4B2AC12A39" )
                           , ((192, 255), "2F3C3E10649160B44321B7F830D7D222"
                                       ++ "699FAE0E834C76C3997985B5404808AB"
                                       ++ "7E6E99AA1FEC2730749213E7F37A291A"
                                       ++ "A6B5AFD2E524C2D608F34D4959930436" )
                           , ((256, 319), "8598D1FA94516B474B69DA83E3C1312C"
                                       ++ "49A05B8283B880B31872CD1EA7D8F1B2"
                                       ++ "D60A86CBA8184F949EA7AE8502A582DB"
                                       ++ "392E85C4D70D3D17B2E57D817A98ED6E" )
                           , ((448, 511), "F86C7489712FB77896706FC892D9A1C8"
                                       ++ "4BB53D081F6EB4AE1C68B1190CBB0B41"
                                       ++ "484E9E2B6FEA0A31BF124415921E5CF3"
                                       ++ "7C26493A5BC08F7620A8C80503C4C76F" )
                          ]
    , testVector256 "Set 2, vector#  9"  ("09090909090909090909090909090909"
                                       ++ "09090909090909090909090909090909")
                                          "0000000000000000"
                           [ ((0, 63),    "7041E747CEB22ED7812985465F503331"
                                       ++ "24F971DA1C5D6EFE5CA201B886F31046"
                                       ++ "E757E5C3EC914F60ED1F6BCE2819B681"
                                       ++ "0953F12B8BA1199BF82D746A8B8A88F1" )
                           , ((192, 255), "4EE90AFB713AE7E01295C74381180A38"
                                       ++ "16D7020D5A396C0D97AAA783EAABB6EC"
                                       ++ "44D5111157F2212D1B1B8FCA7893E8B5"
                                       ++ "20CD482418C272AB119B569A2B9598EB" )
                           , ((256, 319), "355624D12E79ADAB81153B58CD22EAF1"
                                       ++ "B2A32395DEDC4A1C66F4D274070B9800"
                                       ++ "EA95766F0245A8295F8AADB36DDBBDFA"
                                       ++ "936417C8DBC6235D19494036964D3E70" )
                           , ((448, 511), "5CF38C1232023E6A6EF66C315BCB2A43"
                                       ++ "28642FAABB7CA1E889E039E7C444B34B"
                                       ++ "B3443F596AC730F3DF3DFCDB343C307C"
                                       ++ "80F76E43E8898C5E8F43DC3BB280ADD0" )
                          ]
    , testVector256 "Set 2, vector# 18"  ("12121212121212121212121212121212"
                                       ++ "12121212121212121212121212121212")
                                          "0000000000000000"
                           [ ((0, 63),    "7BCD4C5528F4BEAE0FC9F164CEBEC73E"
                                       ++ "D89CE32DA46EB68CA3CEDAA7C7A580FB"
                                       ++ "1C50D291F31C38DB2811864F6654098E"
                                       ++ "141A2213828593A98B7D0020BF0D6D93" )
                           , ((192, 255), "87DCAB67C8D5A90D17AF198D3A22D432"
                                       ++ "BC82C06872F0E61B3A3D1A1FC14527D1"
                                       ++ "E8C3C9CA50E5BF529621C2860ED304F2"
                                       ++ "7E6E427A9BC64D0FC6E2E16BD40C434C" )
                           , ((256, 319), "121F38D31A0ED8A6D72F4C6A4678A7B0"
                                       ++ "D3054A6268D02C9C6766069427722606"
                                       ++ "36CD6D79F81C64412A93F10DB68D1B86"
                                       ++ "962DFC41434B1C65AF4770F7D185514A" )
                           , ((448, 511), "BEDDFB9B60B204E0332726D7D7E90640"
                                       ++ "FF29318A164A9551D9FA477D7E437273"
                                       ++ "A0E08EC35046CAE10BDAEB959F44E9C2"
                                       ++ "A09FFFBAA7A89B7B9F1AF34948FFFE9D" )
                          ]
    , testVector256 "Set 2, vector# 27"  ("1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B"
                                       ++ "1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B")
                                          "0000000000000000"
                           [ ((0, 63),    "944B67EAB62DF3756085CEE577D0C1DA"
                                       ++ "4DD7CD17B85F9B9C51004107C8AA6935"
                                       ++ "7E413AEA37BB512BD8246F2D03E2748D"
                                       ++ "3BB24B60C1FBE4D1A55237FFE3D4D604" )
                           , ((192, 255), "A9574AD5FC6A0D4A57FBE98AB5122A54"
                                       ++ "E2C355524AAC38580C659AE4E906F14C"
                                       ++ "3FB5A096586FA808F5F266182D26C784"
                                       ++ "72B116652EE1874CB5CF007DF2E2BB5A" )
                           , ((256, 319), "EE5A306A60C83E209ACC5F3D60E17D90"
                                       ++ "FDDC0D790BBB7B1EEB635924A4C7AEBF"
                                       ++ "3ADE18F1F2F03C1E74093847B8F9225A"
                                       ++ "9588E92A826444BDD143B38CC3934FBD" )
                           , ((448, 511), "33DDC526B91BD452296DC8ABAEE7C65A"
                                       ++ "E7D8CA37FE66166B67570726639841C8"
                                       ++ "559405236A37A104FAA3F5A1A1932D57"
                                       ++ "FFE36EC16D439B1C291DD11638C50730" )
                          ]
    , testVector256 "Set 2, vector# 36"  ("24242424242424242424242424242424"
                                       ++ "24242424242424242424242424242424")
                                          "0000000000000000"
                           [ ((0, 63),    "0FDF243C21DA8B291097C9F385DFF2AD"
                                       ++ "4FDCA5EB4FA7E4C23CC61FA1A582EB23"
                                       ++ "5AE23454DF6F19B259E498F746F9EF35"
                                       ++ "491F77DC53BD596AACCB9FB7B5EE8ABC" )
                           , ((192, 255), "A92CE971EA8E2ED7614325F0C47CE1D7"
                                       ++ "200B94EEB7FB4E31CDE640696ED6449F"
                                       ++ "B29A9F19EABE323B776EE9460C2448E2"
                                       ++ "DF83206A401074E3254C5AD6C194BD99" )
                           , ((256, 319), "6F988009D4C82F523611DE08FEA23680"
                                       ++ "02FA5A615E8EA831A76C7CABCC92E1BC"
                                       ++ "C02249FD76DDEA5C00FEBC391613857C"
                                       ++ "97CD684B23C6D9B40F1C5254404F7CA4" )
                           , ((448, 511), "61503589A014A6F800A5D93803517581"
                                       ++ "988262122B30755A337F81EF3B326125"
                                       ++ "51ABCE838C0A57795EED2F26173DE6B7"
                                       ++ "E4BB6E37EE7F98383658A7BC47976321" )
                          ]
    , testVector256 "Set 2, vector# 45"  ("2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D"
                                       ++ "2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D")
                                          "0000000000000000"
                           [ ((0, 63),    "3D9EA1F4A3036C92CF9E0D6BB20824C0"
                                       ++ "F57818B3C84DF65AE4A1DE2A058F8BEE"
                                       ++ "242F9BEA42A78383F98AC998BE4B1EA5"
                                       ++ "401BEA5250611CFE6505AA5F43C9A262" )
                           , ((192, 255), "8C2F23B3E0255982DB921D035B507433"
                                       ++ "2EB98C31143E19F5FAA40547D0819157"
                                       ++ "BBA1B6B5C3177AE45074CF5E711195F9"
                                       ++ "281A71E62617F3A1E582D4F89FDAEC4F" )
                           , ((256, 319), "5D1ED872FD20FDE0C98FD76503F538B7"
                                       ++ "538F5061D3A3B12385B4BAE7C8CECA20"
                                       ++ "E47EBD5C96F88D78230B5D3909CA9B0A"
                                       ++ "4BDDA1FD1F561ABEC60524C51559EF45" )
                           , ((448, 511), "EA2F040B9DD538FB258C9289F5CB76B2"
                                       ++ "335C7D05F5B9B2CD591B55AC8FAB882D"
                                       ++ "07EC54EDD33D4B24D6AD69841C219C5D"
                                       ++ "26DDC827C67D0A6AC12D0A4E0DBE9A78" )
                          ]
    , testVector256 "Set 2, vector# 54"  ("36363636363636363636363636363636"
                                       ++ "36363636363636363636363636363636")
                                          "0000000000000000"
                           [ ((0, 63),    "E0E9C87C82202453CDE753D368DA1842"
                                       ++ "9279F0B97446FB12A0436C6BE1AA7514"
                                       ++ "3E98B740F6F9CEC72A1EA38D4EF2BC65"
                                       ++ "E1AF3AE13C5ADF6DA16A2131739C0084" )
                           , ((192, 255), "A43046BAE6A4A2C288CA187C72A21E88"
                                       ++ "047CE98C64147F2F853617A54A3057C7"
                                       ++ "0F48823ECA4B82609924CC9453D57F1D"
                                       ++ "3ACF7D302592BCF9B1439F28B3EE5F34" )
                           , ((256, 319), "08DFF1999015561E0817C20CED5E979C"
                                       ++ "6BED0512A69CCB4C6F6FA480CCE4348A"
                                       ++ "076F549355D22DDC52728F833447DAED"
                                       ++ "83D7012F3F59A8BE495078B72B299753" )
                           , ((448, 511), "C66109B099BAD13AF2F36F5AED7AA0F0"
                                       ++ "0320D8B109EABC7428362B7CC43C284D"
                                       ++ "04EC23DFA4F2A5ED2A7BE2A64CF42F9B"
                                       ++ "F973C6F2AFDB1AB7B7E5F9499B9DE964" )
                          ]
    , testVector256 "Set 2, vector# 63"  ("3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F"
                                       ++ "3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F")
                                          "0000000000000000"
                           [ ((0, 63),    "18B631E89190A2C763AD5F1DBC57B565"
                                       ++ "EAD588F7DC85C3DD75E7D7E74C1D4429"
                                       ++ "E2FB3C6CB687A620EB7050CCD49B54D0"
                                       ++ "F147302BFB7ADC6D1EB235A60338D190" )
                           , ((192, 255), "FE2017B0E26C72416B6789071D0EABE4"
                                       ++ "8DA7531CAD058597AB3742792C791678"
                                       ++ "44C84243B910FCA131C4EB3D39BD6341"
                                       ++ "842F96F4059261438A81423586EEE459" )
                           , ((256, 319), "5FA44FAD6149C7E80BA6A98A8C861993"
                                       ++ "F7D39F1CAEAD07CEB96CBB9BD9153C97"
                                       ++ "8B8957C82F88EC2EDD1BCC207627CDB7"
                                       ++ "029AFC907BBEAFAA14444F66CB9A20EA" )
                           , ((448, 511), "CF4DD50E4D99B8A26A9ED0F8CEE5FC10"
                                       ++ "E8410C7071CCFD6939C09AE576C3A5ED"
                                       ++ "D2F03412E40C8BAD8DC72FAFD2ED76A1"
                                       ++ "AF3BDD674EC5428BD400E2D4AE9026EF" )
                          ]
    , testVector256 "Set 2, vector# 72"  ("48484848484848484848484848484848"
                                       ++ "48484848484848484848484848484848")
                                          "0000000000000000"
                           [ ((0, 63),    "82492EEE44E22AD4DFCA2032BA401F73"
                                       ++ "7D4BC35CE8546EB6314EDC25E69DAC16"
                                       ++ "C8A9EBED6EAB895B7D72BFACEAA14E36"
                                       ++ "3F9A9773E43B077A1991EAC1EEA83EC5" )
                           , ((192, 255), "CB11B43F7E98D75576BB1B1AB33A4E6E"
                                       ++ "CD9CBCEEB36718B22C14F430A8BE7BCA"
                                       ++ "BCBCDE60D775DF441FCD808E79D05FAF"
                                       ++ "E3AA199D45DC174272EA3DD0057D9BD4" )
                           , ((256, 319), "7D237FF28E20F0FDCAE42A7D0D7AEFEC"
                                       ++ "8AF23CF2906E305341FDF8FF75C0B9CB"
                                       ++ "C8F19696CE8D31D15E27EAB0AFFCE92A"
                                       ++ "AFD1BC29E9B80895B3A7CF57ED434D96" )
                           , ((448, 511), "5ED806ACF2490F17AB82438484FCBF61"
                                       ++ "6A17015069B88DFC2C4CE76A2F564E4C"
                                       ++ "5786A7514CE542709E90101094DEBBF4"
                                       ++ "8954F9BF8F4773E06DEE7FB9231AA457" )
                          ]
    , testVector256 "Set 2, vector# 81"  ("51515151515151515151515151515151"
                                       ++ "51515151515151515151515151515151")
                                          "0000000000000000"
                           [ ((0, 63),    "C7FC0F8C8D2064FE05BEC4A641560FCB"
                                       ++ "C41A60718B1DF62AA297E754756CDB68"
                                       ++ "48C5BF60721B49A854A7A4D4BF2D36EE"
                                       ++ "943A3B3922A638293B32F15A7E9A1357" )
                           , ((192, 255), "987A15FE80E62B043B2C7C0953A27D04"
                                       ++ "83B2A7ECC03AD33C2F99FAB7FD2A7EE7"
                                       ++ "0181F7913429F89027E392FC3B73F4A7"
                                       ++ "5E475BA1D7DD4DA0F32D776BBABF270C" )
                           , ((256, 319), "CEBF798ED076B963AC8EA9465F7EBB90"
                                       ++ "6E09F80247C1FE09C86D1BEF3DE4F4AF"
                                       ++ "94B51FECC1C58E1E8CD225C2F68CCEAF"
                                       ++ "C36C029DDCE9380AE9FBC867E145F658" )
                           , ((448, 511), "FD7E885A72C796E642EA628C6ECDC508"
                                       ++ "9F465F57E55D51170C039B253B14EB9D"
                                       ++ "195A3712CDEA2624A5382880192DE3FA"
                                       ++ "0DA2A86EF3A61220DB949596FE1C318F" )
                          ]
    , testVector256 "Set 2, vector# 90"  ("5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A"
                                       ++ "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A")
                                          "0000000000000000"
                           [ ((0, 63),    "6C3645C8621D8E7286911278BAB37C5E"
                                       ++ "EBAA2AD321AB8ECA62D13372156F8B87"
                                       ++ "FB87FBE02B1EFE39AB0EBE41553E5348"
                                       ++ "073053048A0D4DBDA1880230CD23A4F1" )
                           , ((192, 255), "BB161E8441B29DE15C9A02F447766354"
                                       ++ "E7E590B42AE566935F0A6D7E864AF5EB"
                                       ++ "B288C0C63812B0917970547225899573"
                                       ++ "7C804E58F7BEA1596B7343B0CBDC6AA3" )
                           , ((256, 319), "6EC6A41251D6FE041CD87EB3996369F1"
                                       ++ "390E649F012712F9DA4D1F4DFF96CF74"
                                       ++ "91CAA6836C09BA8C55ABB656B4F51F7B"
                                       ++ "4AF829B5DC89F460287EFAD064C44F28" )
                           , ((448, 511), "3D54A399D5B92252CCF9E6A0C054D4A5"
                                       ++ "EDBFA58A3B53981BBA50EE9BB379D71A"
                                       ++ "C9775A0D793AFC79A64C708D0F9A7D7B"
                                       ++ "E061D5A5D50DBF32480AABEBC128D198" )
                          ]
    , testVector256 "Set 2, vector# 99"  ("63636363636363636363636363636363"
                                       ++ "63636363636363636363636363636363")
                                          "0000000000000000"
                           [ ((0, 63),    "D417644E8A37FF8840772A55960C4B06"
                                       ++ "4DA371869EA07FD02D7F8EFEF0BDB7CE"
                                       ++ "308173B8BAFDCA6064CEBE09609377B6"
                                       ++ "542CE73D44A0134C95C452D9B83A4B35" )
                           , ((192, 255), "2974AF76C0EB09874EFAF061BFD45636"
                                       ++ "E6AD9C2BA71A1B4FAE493C04205B5CCA"
                                       ++ "A1D361DED0F1BF8C2FF2DE70F4B68E1E"
                                       ++ "B1B6E63B19EE1842DA4ABC52C88714D8" )
                           , ((256, 319), "934392340254B83FA7A9888D1CA9959B"
                                       ++ "A221FF1C487B214FE6703C4BCE02EF62"
                                       ++ "4DE46A76670712B381E2EE017B67DBAA"
                                       ++ "3726CE1CFB39038FD0059EFCB2346385" )
                           , ((448, 511), "F234ED6FEFF11821E19D73E31BFAF745"
                                       ++ "126D80E0743623A179303C5A7827582A"
                                       ++ "ACFEE4845E8D3FD98AB990C710020B42"
                                       ++ "542DAB392D6A1BFE058E200FEFA00006" )
                          ]
    , testVector256 "Set 2, vector#108"  ("6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C"
                                       ++ "6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C")
                                          "0000000000000000"
                           [ ((0, 63),    "1456A98D271F43A5FF29B3D0BCC35B78"
                                       ++ "50C4D9DA5BBA43B752A1A541A4FC88DC"
                                       ++ "0FC4C89F35ACF1B540F5C3207A0BF359"
                                       ++ "490D482232936E5C0B818C3DE6EF2012" )
                           , ((192, 255), "E8DFC363183330BBCC8498913A28545C"
                                       ++ "6905F858D314939FA148C4C6600CD23A"
                                       ++ "941F88F2FF08D7567202F335F5A90A0E"
                                       ++ "A92B9D73A2C710CFE22BE0D180BA1A42" )
                           , ((256, 319), "77ACAD59AC794EC38C13805E9638F145"
                                       ++ "DEE96C36C9C07A1811DCC1531A462144"
                                       ++ "AC1F4B2245A570C42B25EB646D4655D6"
                                       ++ "EA646776B0445C8B5670AB2B11203823" )
                           , ((448, 511), "9A1BBE72AEC868E45B28B9FE3570381D"
                                       ++ "A759D1484B710A2AFB385DB7EAC5A2C6"
                                       ++ "5E2EFF9204C5DF6A684ED55C2D09FBD1"
                                       ++ "7E2FB6B4FF4BAD3ABD201DCEE340305A" )
                          ]
    , testVector256 "Set 2, vector#117"  ("75757575757575757575757575757575"
                                       ++ "75757575757575757575757575757575")
                                          "0000000000000000"
                           [ ((0, 63),    "8F04C8F40319569CB4B04458528135E8"
                                       ++ "35AF2C69561F0F0F5B6009B540B85ED1"
                                       ++ "BC7612C9EC7A200B08AEDF07DB08ABC3"
                                       ++ "9FA48E63AC81974175AE3A4AC9429985" )
                           , ((192, 255), "DD98FBC3465BBD56ED0BF2F2367498B0"
                                       ++ "E2854E514A27C7410AAF8E0B44117EAF"
                                       ++ "A5EDA0C7FA2106C03DB8AF62E5ED136B"
                                       ++ "4BCA0B82CF2EA19FDADE4101C57117E2" )
                           , ((256, 319), "7CA321B64434A90CE08E00A99D9456CB"
                                       ++ "7A0779D4F0FC12346C01A5A1310528DD"
                                       ++ "2E0EA2F58A8795BD138687645A7054DC"
                                       ++ "2FA74835B1B45F4B68E3CEAAA315C250" )
                           , ((448, 511), "076AB5564DB74D830CF96E6B90897E5F"
                                       ++ "2E597619B47FF74B190C16735E902BDF"
                                       ++ "111FA384ED3F8055343F4561C731F783"
                                       ++ "7072FAB81825304DC3D4CC02404E539D" )
                          ]
    , testVector256 "Set 2, vector#126"  ("7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E"
                                       ++ "7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E")
                                          "0000000000000000"
                           [ ((0, 63),    "DFD428440260E1B64579A6940EE53907"
                                       ++ "8CF48977E4B61DD0C708B52B42A607AB"
                                       ++ "C0A0774F49FD8599E4A4CA3B7C54FEDC"
                                       ++ "353D2467DEECDB9FFC8350C79414CFBB" )
                           , ((192, 255), "F4C7C343C6DFB6F7EA25DBF6DFBD31D2"
                                       ++ "595C45C4CD1C057308FFA60C1AF1BBCA"
                                       ++ "888C6C8097E97319566A7EBD80DA4F0E"
                                       ++ "DDBD22015CC363E5AC01BE42770660C8" )
                           , ((256, 319), "F1792B445D52BD4FC99557ABBECBCE74"
                                       ++ "257A62EEA110EF9CB3CB0388922A7FBB"
                                       ++ "5FCBCE5BCE44818F930284E4E360973D"
                                       ++ "49607E1B0E1D97C618EBA4D909A50375" )
                           , ((448, 511), "7A2EB3ABE2F83C4B40A15F4AAA89D5C9"
                                       ++ "72B911AAFFF5069FA3E7396162CFDBBB"
                                       ++ "6A16E222C15878D9C8A00AD8201F1889"
                                       ++ "9F060851A3147AC2F3385FD8144BCD32" )
                          ]
    , testVector256 "Set 2, vector#135"  ("87878787878787878787878787878787"
                                       ++ "87878787878787878787878787878787")
                                          "0000000000000000"
                           [ ((0, 63),    "47756F1D1EEDDF06790A5E39083186D3"
                                       ++ "16E3258B9C5B7D25E478E817308E2B90"
                                       ++ "A5DC4A8C03A38AE1757B6EFAE73B058A"
                                       ++ "7CEA675CEE9A01E9BBC7B15DC5424E64" )
                           , ((192, 255), "FE6FB2E0BDF120B585D082602D2648D6"
                                       ++ "D95D14C3E8DF44F7D9BF650709578C0A"
                                       ++ "A5D775BAA12A3C1153CF44AE2A3BAC49"
                                       ++ "534210F8BB8AAE7F54DF049AE368678F" )
                           , ((256, 319), "DA0D9214302984F36B92EDCA76765B8D"
                                       ++ "5E748EE13176CFA41345AB0EFBD7CB54"
                                       ++ "737DC606DE60E4355233E63B1EDAF48A"
                                       ++ "B84DF854E47D1D746B3AA5CCC0A5DA62" )
                           , ((448, 511), "8373EFD791B51A07B840A7FACA4307CE"
                                       ++ "9F5FB71A0C7891CEF7E7754A414B61D6"
                                       ++ "593A5EEB782FBF28998F4174C63733BF"
                                       ++ "A7EE172290A0A854AD6C36757AEE0911" )
                          ]
    , testVector256 "Set 2, vector#144"  ("90909090909090909090909090909090"
                                       ++ "90909090909090909090909090909090")
                                          "0000000000000000"
                           [ ((0, 63),    "6AB7A8C769386FB6067059D0EE3DBC97"
                                       ++ "1EFAEF4AC10C74A2F17527EA5A8C6E0C"
                                       ++ "DF1FA10F27A29911BB57BF3E7A6DBDCE"
                                       ++ "4AF3E7BB730F47AC79DC917DA646A8B7" )
                           , ((192, 255), "1DD701A2698617855C38017B0ADE1E17"
                                       ++ "D22D9717E21AD8635CE6A40CECC7EE43"
                                       ++ "83D5483F414B9F2285D200500CCA85C3"
                                       ++ "D45F4F25550E3701B675D7E1B8266C6B" )
                           , ((256, 319), "5D331C1544CFD44E3588C2EA0D889F44"
                                       ++ "D5742E7AFE9581CAF23CB668B0530C84"
                                       ++ "A89D63F948969DBC0D0574911EC0307E"
                                       ++ "CE9CF38C5FCDE75462D1C472455A78ED" )
                           , ((448, 511), "A55713DFAA272076529BC5A33558A7D5"
                                       ++ "206C1C070648DBAA348C78556631AD99"
                                       ++ "F8F16DDDA2E5779B155DD9377A8E575C"
                                       ++ "257FE7E08ABE9B3A378027EA06539810" )
                          ]
    , testVector256 "Set 2, vector#153"  ("99999999999999999999999999999999"
                                       ++ "99999999999999999999999999999999")
                                          "0000000000000000"
                           [ ((0, 63),    "E548ECEAF4B4AF1F8572F7113C7D8FF9"
                                       ++ "61837C15ECC6BEAAB80F38CB15022B50"
                                       ++ "BCB1FA414A798C954DAFB572CF22A9A4"
                                       ++ "D82F7561186C31BA0199EAE1678CC4CF" )
                           , ((192, 255), "9E5D061279348E0D5DA552A82DDD3795"
                                       ++ "37F928DCA393AE75AED13F63BD60DEE4"
                                       ++ "32C96D1B2365B59FEE3C0E18515966D6"
                                       ++ "642F2E156C30C704A77DCB5629AC6167" )
                           , ((256, 319), "9CDCAD9CB247AB21BA9E93C936936994"
                                       ++ "C6C320841C745D6DFC85110367B36C88"
                                       ++ "67CFAB60F6A67A1656C645BFDBF196AC"
                                       ++ "974A4165BF81FBE715CB6C3954E217FD" )
                           , ((448, 511), "FE5134E8B0BC016D3ED3594B6EEF2F06"
                                       ++ "FAFE2F4C89CB4E2627B232BACFDCA8A4"
                                       ++ "80B1C55DF4C0AF1E630A617CEDE0A48F"
                                       ++ "900A9CF815362C098A76D29360414735" )
                          ]
    , testVector256 "Set 2, vector#162"  ("A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2"
                                       ++ "A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2")
                                          "0000000000000000"
                           [ ((0, 63),    "D0854334E4619E3EFBB2A53D59F89866"
                                       ++ "F67220CE00A3116313FB9CB645339766"
                                       ++ "0CA976A8B3477F76FF8FA485D61E3758"
                                       ++ "3DA5F35A8FAD678B7C2B9EC97321DFD0" )
                           , ((192, 255), "92D4924C3E682EECBF9AD3A5453BE7BD"
                                       ++ "56D9FD73F16BA0CA09FBD0C136BCD595"
                                       ++ "2FE55744B1871E4C8726611F291B282C"
                                       ++ "2219C817C88086A5A7BDC513DCCA473D" )
                           , ((256, 319), "CAC309E4AA3ED635D68E5AFD9F4CB0BA"
                                       ++ "DB229E8EB560B16645CA2A71B35B7C3D"
                                       ++ "757C156983F7D053B0430F9634402B8E"
                                       ++ "4FDE6926135473BA8560C3AE1FD5BF48" )
                           , ((448, 511), "980DB26FDBF49D5D890B65EB01AAEBD5"
                                       ++ "CC118812BDE441A71871206D67683889"
                                       ++ "828622C6336DEA09DB6ADE0772A3D091"
                                       ++ "F77B1F3115E1341EF11F41F7CD0505D6" )
                          ]
    , testVector256 "Set 2, vector#171"  ("ABABABABABABABABABABABABABABABAB"
                                       ++ "ABABABABABABABABABABABABABABABAB")
                                          "0000000000000000"
                           [ ((0, 63),    "6CD6B451B1C793485006B3B51470E6AB"
                                       ++ "20163502C30240C4A3C6406482A2770D"
                                       ++ "550AD77D0091632C719BA33769823D2D"
                                       ++ "8147396466F1A2A857060A42ECCE0A0E" )
                           , ((192, 255), "81298474E6D86A66AE4CBCEE495D8740"
                                       ++ "502CBE5CC91174865A615B193B55BA4F"
                                       ++ "CD2337667292D3F3C428B9FEF090207E"
                                       ++ "2DEF037917A2244FFD3AE8161CEBA42A" )
                           , ((256, 319), "367B062DFFD72A6EF6CEB3AE7FE59684"
                                       ++ "690F40A9F276E8021994ED475BE1F08F"
                                       ++ "A5C99E3A1AE1E68A92D02C5C14BE0E67"
                                       ++ "A1B989E7033274993D1685D4B2DAE6D0" )
                           , ((448, 511), "43C53B82CFBB199FFF9C5719ED1EF470"
                                       ++ "AAAD578C5778A9DD3C2D77C7BAF41CC3"
                                       ++ "0F5F7B4C91FED81E9A661093EE20FC3B"
                                       ++ "BA55FF8447C899C6E12A0A0F5ECE3BA3" )
                          ]
    , testVector256 "Set 2, vector#180"  ("B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4"
                                       ++ "B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4B4")
                                          "0000000000000000"
                           [ ((0, 63),    "EE879D01C8E20CE8CACDDB464348F69C"
                                       ++ "6551F70383A82933C3A765B8AC138581"
                                       ++ "8D67C69841FF2B4B8BC209ECFC0FE765"
                                       ++ "C44C42C9CD6EFF90E0A6DAB153F52D04" )
                           , ((192, 255), "8D7D377A3072E9571F9AE00D25E875A4"
                                       ++ "D9BAB98A3EA348BF823F12F44DABAE28"
                                       ++ "317BAA3A71EB3D7C4C2EC3EF87E828CB"
                                       ++ "862FBFC99C7ECBC629D22DB8EB82156D" )
                           , ((256, 319), "97B547A3E920FB054416A5787EAB5C76"
                                       ++ "38FA6CCDEC816613FC855EAAFB4887C1"
                                       ++ "3A38094D89570BF17E55E5E1EC275ECD"
                                       ++ "122142C9126DE5E9411F06805071983F" )
                           , ((448, 511), "CCA815558FFE08873C9AF373FAA546B2"
                                       ++ "FB3EA3059EFD02CB778D01962E87EFA8"
                                       ++ "5F24BC5BEFD4ED02C986C0229D70ABA0"
                                       ++ "D4E97328780FBD0ECB367A8C085414E9" )
                          ]
    , testVector256 "Set 2, vector#189"  ("BDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBD"
                                       ++ "BDBDBDBDBDBDBDBDBDBDBDBDBDBDBDBD")
                                          "0000000000000000"
                           [ ((0, 63),    "DED8C79CC623162C2074FC7B4876F754"
                                       ++ "1B959209AC6573E6D25D1F1E649CC241"
                                       ++ "31A2F1B1B9E9E0FA639F8AF373CCAB88"
                                       ++ "3C659001BD120449997871E6A1D5AD8E" )
                           , ((192, 255), "1E946CF03C4C89D19DDB9C48EACFE7FA"
                                       ++ "A48235899DF49232CE2A586130BAD63D"
                                       ++ "52540151FBC02E3BFEF082A63A900C42"
                                       ++ "0D6D7A11E289C34387A6155ABB71816A" )
                           , ((256, 319), "3CCAA2AEA81296ED9171B608FD8DEAEA"
                                       ++ "3EA5B8A87B17B10751A01713EDE6A156"
                                       ++ "652783C26C0247E347860C06AD633AAE"
                                       ++ "2C0AFB239291A6E7729F8838A4D97533" )
                           , ((448, 511), "065DCB330DDC528BD42DC6A0F85179A3"
                                       ++ "531CF900DC5F7D3B5455DC49D451161F"
                                       ++ "9AFD79A619DD951C854019412532D33C"
                                       ++ "9DE6F9AE44394208653CF12D316F4A70" )
                          ]
    , testVector256 "Set 2, vector#198"  ("C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6"
                                       ++ "C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6")
                                          "0000000000000000"
                           [ ((0, 63),    "36AFBAFFF746195D8784CB72A16D12AA"
                                       ++ "604CDBF567955F15FB55DD42FAE8DDC4"
                                       ++ "E6CEA63B6F8E2815F3094005E403FEA3"
                                       ++ "0EEDD68B5F2573EFD03A4E2BC41AEC32" )
                           , ((192, 255), "4F7E1CE5E727D83989222ACF56776F0A"
                                       ++ "FD1B00E9A5734408E1513313E0CA347C"
                                       ++ "C37D8DE7AF4F6C5C7EF311BDA97BD8F4"
                                       ++ "52F89B4D44411D63105BECADC661D558" )
                           , ((256, 319), "2677C65207F10008A28E0D3D2C7D43A6"
                                       ++ "71A96CB9A98ED1ECDEBA8F5AFAF4DDF3"
                                       ++ "F7B078346EB1DAEB1047D2E656EFB331"
                                       ++ "F3A71302E6FB547568D6A8A2871EB5B2" )
                           , ((448, 511), "C39BC4103ED0D8FE8C7D5FC072C94080"
                                       ++ "DF9DAB70F627D8BD68719A721836554F"
                                       ++ "3A2CFD08616170F4E3C3B0420BB41FBE"
                                       ++ "9A84C43D405B9EE32285BB5051CD5E83" )
                          ]
    , testVector256 "Set 2, vector#207"  ("CFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCF"
                                       ++ "CFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCF")
                                          "0000000000000000"
                           [ ((0, 63),    "AA68F6EB41DB62A2C5E4E9AAF21D7D43"
                                       ++ "1C29A66303854A68EF737872CBF7C505"
                                       ++ "918B87CE4DB6B3D84BC039906AC0561D"
                                       ++ "F79F0A57CFA762B8B9C2991F1DC98032" )
                           , ((192, 255), "7BC0564BAF3C88CF14FCD2020433CEDF"
                                       ++ "65EE68DF4AFAB7E040DFC396A856617F"
                                       ++ "677217529B839EB9DF47AFD6758CAACD"
                                       ++ "75E734FCC653ED5AC25C8A7B1AEBAA49" )
                           , ((256, 319), "AD21BBE24EA84C0859B2EF3E09070493"
                                       ++ "6A6D2A97DF912207D3F50D63FCD56676"
                                       ++ "61A47AD0DF1FA8DDE08EAD7201AF15FA"
                                       ++ "85BCBA0962D7921397E35E60149BB4EB" )
                           , ((448, 511), "8914307989CD704120A6DAC52789B845"
                                       ++ "7260A2939CA0E02A4C41C46ECE890305"
                                       ++ "9F58A2B0F3D93B45160D08A13737D51E"
                                       ++ "984B97CD4A28DC2D92155FCADA3F8033" )
                          ]
    , testVector256 "Set 2, vector#216"  ("D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8"
                                       ++ "D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8D8")
                                          "0000000000000000"
                           [ ((0, 63),    "596EA70BBA1A4DE2F8ED2AF37A0CE6D1"
                                       ++ "2443354659CD0C41203EB345E160CF05"
                                       ++ "6F8D71314AA7221D86F868304F34D5B3"
                                       ++ "ED4D51072FE7B12568B859077B6F920D" )
                           , ((192, 255), "26716254A9C7067808EDC0D31D54D289"
                                       ++ "88A3F655C10931E217B3C9A8A4B557D2"
                                       ++ "8AD6C701612A8D848FED1589CCFBBE7B"
                                       ++ "566496F4662B1D98FCFC70C1716E5347" )
                           , ((256, 319), "B33C15E9488DE8A97AFE67FBFAF47FFE"
                                       ++ "5C3934B05B5E2EA061A41A2BF0D81FB6"
                                       ++ "054C824B492775E3E8300DAD609BCEA5"
                                       ++ "837392668C0B54FECE2F2945F18160D3" )
                           , ((448, 511), "A1F72ECB02649F01D4396574EA80BBCB"
                                       ++ "8934FCF989CF1D7CF7410B0A93E08C10"
                                       ++ "0A229C952DA999789662E1666CA71C65"
                                       ++ "4DBEB2C5BBC20BB67DF67CD39B51B4CB" )
                          ]
    , testVector256 "Set 2, vector#225"  ("E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1"
                                       ++ "E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1")
                                          "0000000000000000"
                           [ ((0, 63),    "6D221A5561813E4B6BF1A3821F0BC95B"
                                       ++ "3D51004ED29EAECD26016E5B7F628BA0"
                                       ++ "6B2BA4D650D685C3BA9FB51E305EEB36"
                                       ++ "A11CA08C431E0740D59D521FBDDBF716" )
                           , ((192, 255), "9C9EEBCA7428A88562FAD4EC9800EB7D"
                                       ++ "E4EBE571855B40D3F1D9770236EF0131"
                                       ++ "70A6BF8CF9C1880A1BC3C58193777098"
                                       ++ "89384D19F4F9D6E8098E8E326B9AC4B7" )
                           , ((256, 319), "86ECBB7CA8E1526F538805A692C354B8"
                                       ++ "E335BAC919CB4355C15B40D721328BE9"
                                       ++ "81105395FD27BB6F0515A427469DF557"
                                       ++ "DC92EB010C49C332BFEB1A98154BF0AA" )
                           , ((448, 511), "0503DAA102F9CDFBFF854D6015BF484A"
                                       ++ "201F69E6E789A757B8DAB005D5859027"
                                       ++ "849ECA4E951AE28126FB6C63BB65EF61"
                                       ++ "94C9661F9E40CAAB817CBE89595096EC" )
                          ]
    , testVector256 "Set 2, vector#234"  ("EAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEA"
                                       ++ "EAEAEAEAEAEAEAEAEAEAEAEAEAEAEAEA")
                                          "0000000000000000"
                           [ ((0, 63),    "304665A82B0838D4EA0A7737855CEAB0"
                                       ++ "44583FBF2F8E68D7B3B191600ADAEB33"
                                       ++ "538942A71998F68DA9A0D4BAC36A5052"
                                       ++ "CBEAEFFCABC6B506E5F805F8105D5E79" )
                           , ((192, 255), "96B62FE40229E2CEBEAE44431F01A0A4"
                                       ++ "3FA080D685215BEA4705B6B78187751B"
                                       ++ "E1DFA0DCC1C8D6A2040C0716F524CF40"
                                       ++ "42889F743A3EDC01EBDFD3A6FF3E92DD" )
                           , ((256, 319), "D1667A839D7725E602FD36A69117D039"
                                       ++ "AE92EC7032432323A61AFB1602F17E4F"
                                       ++ "B66F0BB5A5F4C54329F7217497B3546F"
                                       ++ "FF9938966B05789E0CA65CBF34DB1B2D" )
                           , ((448, 511), "3557FC69A9D44C66FB022ED8D4D349C1"
                                       ++ "D82A41DA40E3687B197DFC070000B69C"
                                       ++ "2FD9B1F9F99C63BF3ED82F2CCBD2A6ED"
                                       ++ "20A14ABA05F6855078DF5C73A4D50493" )
                          ]
    , testVector256 "Set 2, vector#243"  ("F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3"
                                       ++ "F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3")
                                          "0000000000000000"
                           [ ((0, 63),    "BF9634C2D81B6400C2ADACFCC0C353CE"
                                       ++ "3AC45A2EB636AE9D2D6B8DB6107511C9"
                                       ++ "399FB22CA2DF6406307EADEED423E72B"
                                       ++ "72411E11530B1814AB196A74DFD4FA61" )
                           , ((192, 255), "50F32FC8C94BEFCE5E51F3E774134ACA"
                                       ++ "D60BF3DE49BFE1F17DDD88395C4880AC"
                                       ++ "926528971A3D74796303A4064F67733B"
                                       ++ "A2AB545344B97F555525C0A5611151DE" )
                           , ((256, 319), "A6E426963373DCDCE54C1827F683859D"
                                       ++ "F11857D7BEB1EEA10FF137CF6B395635"
                                       ++ "53C79E92295B1FA385C59BC201612C70"
                                       ++ "39341B55D49139B88A16544AEDBDA967" )
                           , ((448, 511), "EB50C1AFCDFBF83EDA42011C141B67CD"
                                       ++ "041598209605800EAFF2EE6A99A6C958"
                                       ++ "9621B778FA4DB6D2FC4980030B86F3C8"
                                       ++ "670B46BED56A511B9A18E60B1FED27D5" )
                          ]
    , testVector256 "Set 2, vector#252"  ("FCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFC"
                                       ++ "FCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFC")
                                          "0000000000000000"
                           [ ((0, 63),    "356DD71DBC2B216B7A439E07BCC1348F"
                                       ++ "769F7EF482486C92E8FD8EB050224838"
                                       ++ "AB1F4DFCD2FB196AFD4C4FFBF51B9124"
                                       ++ "6BF45AE8131B8D5CAFA29FC3025A3597" )
                           , ((192, 255), "C09481306DB9FF12F1798A21A3031921"
                                       ++ "B237E1B54A73F724CC0378379DB2FD86"
                                       ++ "8DF08983A3D26C32379E3B132A6F1766"
                                       ++ "646A963AA56C8F5D45B35F79B24D27C0" )
                           , ((256, 319), "6C198E30BBAD2E329A7A3ED5C383340F"
                                       ++ "90EADD9F44AB7F339E6BE9217366188C"
                                       ++ "4C8D721BD6DC5D5D192A8E854013EBE2"
                                       ++ "66633893015AFBED28EA42F928B27F60" )
                           , ((448, 511), "FF9B8ED2074ABD83B51AA93A65E5E303"
                                       ++ "774CD6874D344236B1EFD39A3605984E"
                                       ++ "DFEBCFB5B41AC09AAD500F71AF6D77A0"
                                       ++ "7CE81A5E0E1E29C857609143B5BE0BA6" )
                          ]
    , testVector256 "Set 3, vector#  0"  ("000102030405060708090A0B0C0D0E0F"
                                       ++ "101112131415161718191A1B1C1D1E1F")
                                          "0000000000000000"
                           [ ((0, 63),    "B580F7671C76E5F7441AF87C146D6B51"
                                       ++ "3910DC8B4146EF1B3211CF12AF4A4B49"
                                       ++ "E5C874B3EF4F85E7D7ED539FFEBA73EB"
                                       ++ "73E0CCA74FBD306D8AA716C7783E89AF" )
                           , ((192, 255), "9B5B5406977968E7F472DE2924EFFD0E"
                                       ++ "8EA74C954D23FCC21E4ED87BBA9E0F79"
                                       ++ "D1477D1810368F02259F7F53966F91CE"
                                       ++ "B50ECD3DA10363E7F08EEAB83A0EF71A" )
                           , ((256, 319), "68E43AA40C5D5718E636D8E3B0AB3830"
                                       ++ "D61698A12EB15BD9C923FF40A23E80BE"
                                       ++ "026B7E1349265AD9C20A6C8A60256F4A"
                                       ++ "CD1D7AD0DCBE1DFF3058ACD9E1B4C537" )
                           , ((448, 511), "343ED5D011373AF376308D0B0DAB7806"
                                       ++ "A4B4D3BF9B898181D546EFCF83D7464C"
                                       ++ "FC56AE76F03F3711174DC67AC9363E69"
                                       ++ "84F5A447BD25642A00754F1133BFD953" )
                          ]
    , testVector256 "Set 3, vector#  9"  ("090A0B0C0D0E0F101112131415161718"
                                       ++ "191A1B1C1D1E1F202122232425262728")
                                          "0000000000000000"
                           [ ((0, 63),    "0DD83B7F93629BA8E489E30FE4B6EE54"
                                       ++ "9BAFB44CB794AAEF2EF07116649FD4C4"
                                       ++ "4DAC52560EFB34FF1A2E56FC0DD86F2D"
                                       ++ "56C2C5C97089FC4C35C6788F36E6F142" )
                           , ((192, 255), "19A8C09135CBB83C6140BBEB60099BDB"
                                       ++ "469178F58B6DC87AD2B33CAE53A83B46"
                                       ++ "A3BCE1289A68528D5A32A8867587FCC7"
                                       ++ "F4DFE8EEA78BB2A9C40B9F6D8797BFE3" )
                           , ((256, 319), "2E4E97BAAE813AD2C14848ABAB7C51A7"
                                       ++ "4BF3153C63101F4E6E4EEA56B470F0A6"
                                       ++ "78FAC3AA6CC300A51A7A345356D3FE1E"
                                       ++ "3A56242086CA61A1E8E43F6703CDF6DE" )
                           , ((448, 511), "306FBEFC44132B66D527F5E75D171868"
                                       ++ "EE8CBC6DAEFD6FC5B3730541CEA82CF6"
                                       ++ "7D41B8783D75117D266B924502D5AA5F"
                                       ++ "28FF44A13AA2179DD8F0F4AD4B29024F" )
                          ]
    , testVector256 "Set 3, vector# 18"  ("12131415161718191A1B1C1D1E1F2021"
                                       ++ "22232425262728292A2B2C2D2E2F3031")
                                          "0000000000000000"
                           [ ((0, 63),    "4B094A8031FEA02C5CBDC1E2A64B13A9"
                                       ++ "A0976897FCBD92A15738330CD1F85448"
                                       ++ "EBD8B7E61A76855C64BE1BE78034ADEB"
                                       ++ "FFDEDFCF064AB92744760DFBF59F0A9D" )
                           , ((192, 255), "F807DF0420C6D87DAD3A1811A96B5E4D"
                                       ++ "2B2F284CD9130F51D307521BD2CABE72"
                                       ++ "1F1BAC0EF6219B7ACF8923C026C7F9AD"
                                       ++ "8762CC9A9F8847750511D3697E165689" )
                           , ((256, 319), "AFB3798B54C003AA6C05C7893C5DB290"
                                       ++ "AC7FAFE8C25D3E66AC699BBA3A880330"
                                       ++ "70D17C0314DAEAF51DBDA0C9DF36B713"
                                       ++ "A913BD397B41DA7FF410A593568AB2BE" )
                           , ((448, 511), "67AFD443E67F5FF76A247EFCF3D54649"
                                       ++ "0649CDE396FE3AA34549C3ABC8F7447D"
                                       ++ "DB7A666C0402AFA25ADC47E95B8924B4"
                                       ++ "B1C955C11A746FD4C0DA15432C1B83B7" )
                          ]
    , testVector256 "Set 3, vector# 27"  ("1B1C1D1E1F202122232425262728292A"
                                       ++ "2B2C2D2E2F303132333435363738393A")
                                          "0000000000000000"
                           [ ((0, 63),    "AE39508EAC9AECE7BF97BB20B9DEE41F"
                                       ++ "87D947F828913598DB72CC232948565E"
                                       ++ "837E0BF37D5D387B2D7102B43BB5D823"
                                       ++ "B04ADF3CECB6D93B9BA752BEC5D45059" )
                           , ((192, 255), "CF7F36734A7AD1EF4D9A4AA518A91C14"
                                       ++ "64184688F31E5E775E879E01E82FB42E"
                                       ++ "AEE8F382AA0701D54AF5DB788858CCDF"
                                       ++ "801DED1E18BA4195019AA3111BA111AC" )
                           , ((256, 319), "AB84E643D214E8DE9274720A1557A1E0"
                                       ++ "471F00394934A83A324D4270949BD448"
                                       ++ "A7BB6B5D5FA40E9831AE5B4EA7D8D34E"
                                       ++ "071EB56EFD84F127C8E34DA9BF633B46" )
                           , ((448, 511), "E757CA957797D6416E17F852AFFBF191"
                                       ++ "AF98EB8CF73DCBBA0BCE8EFA29B958E3"
                                       ++ "9C0085F0076E0B4E31289A4F2DF35855"
                                       ++ "ADD6BBEC725FC2860D4F49AB4EEA6C87" )
                          ]
    , testVector256 "Set 3, vector# 36"  ("2425262728292A2B2C2D2E2F30313233"
                                       ++ "3435363738393A3B3C3D3E3F40414243")
                                          "0000000000000000"
                           [ ((0, 63),    "5DDE22EEE0ED12CF83F433441A3799B3"
                                       ++ "A4415A2018A60BDE0A0F8E08993820C8"
                                       ++ "20998D420F346D8B808CBED40FC7CBD0"
                                       ++ "CC43949B0A16F0EF2577CECAD03DCAD6" )
                           , ((192, 255), "5C86A6AB19AD083676D609D2C094FFC2"
                                       ++ "921CD8D4580815522BA72AA20FEC59D5"
                                       ++ "64F1EDF2E2AE4810C69701BCD515A939"
                                       ++ "D9C156254F28DE5C90C6CA2B0A385D53" )
                           , ((256, 319), "956A71BB6344DDF03A8B828A03FEA914"
                                       ++ "8585BB8D21E52134F1FA9541A57519F4"
                                       ++ "4C2D56C8746E9FB40EB1FCF3551A5F95"
                                       ++ "38B90606924F3D082987B77C127D1DB7" )
                           , ((448, 511), "2160DB576116DD75880E4DE9A7505308"
                                       ++ "05EBD00F48B6BFB62679F93EDBD42766"
                                       ++ "A51AD3052C64174B5B027F6D5DD02059"
                                       ++ "2F5BBC369D48708295259F4B9519B19B" )
                          ]
    , testVector256 "Set 3, vector# 45"  ("2D2E2F303132333435363738393A3B3C"
                                       ++ "3D3E3F404142434445464748494A4B4C")
                                          "0000000000000000"
                           [ ((0, 63),    "BDF4E0BB6B36D01A31EE2E76F2379D33"
                                       ++ "286ABFA82F6872677955777DEE0B1662"
                                       ++ "A65D85EBC56A7995A6F6CF995154C444"
                                       ++ "C27CEF3EABC85B8985C7FA94C8ECB065" )
                           , ((192, 255), "8835BF6D66FD567BCDA956673D9DA182"
                                       ++ "701921B79AAAB6039D65ABE1C7178923"
                                       ++ "BC39C8A56FDEC8FEAAC4C29707914F68"
                                       ++ "CA6CBEDE4DBE9FEAAF84DA2DFEC56E96" )
                           , ((256, 319), "A2751597632CF806C8246F7F9D9C4A72"
                                       ++ "DE85C8C0C36A769F32A062DFCD45635B"
                                       ++ "0C7131BFB38CE253886D4918CC4B7DBA"
                                       ++ "780CAE5FA0F22479F445C0AD1285F35D" )
                           , ((448, 511), "1130339E16298874524D18F68266246C"
                                       ++ "A0B2060607B60689D025BD30BC6DE7FF"
                                       ++ "5DDB90249319C9EA13195200ACADB595"
                                       ++ "14D56FC358D7A0D3BAEA374E34EA2E9D" )
                          ]
    , testVector256 "Set 3, vector# 54"  ("363738393A3B3C3D3E3F404142434445"
                                       ++ "464748494A4B4C4D4E4F505152535455")
                                          "0000000000000000"
                           [ ((0, 63),    "51B180F1C9C31388F8B3DE8734F3918F"
                                       ++ "F6DEC759689E6A54D0EAF8734DECAB2C"
                                       ++ "A2ACA4DFAA260AB781769B83CF94C2A0"
                                       ++ "166F2643585CAB42220D200F92074363" )
                           , ((192, 255), "147CE4098C9884493CF00DD28B6439A5"
                                       ++ "B794F871CCC4FFE349CABF3963C6BACE"
                                       ++ "D799AAB7F778B59473EDE8CB475056A1"
                                       ++ "E7F5D0BE68DE84C535A8FB67724E0C6D" )
                           , ((256, 319), "7F0BCA1B790CD5C8F8CFD047AFE1C5BF"
                                       ++ "DDA8C8E0BBAF0567D4AE6B63C9E32770"
                                       ++ "51D1200ED8740D60FBBADC20CAC825A0"
                                       ++ "819CB66398FF7CFA38F3CE5CF23BAC37" )
                           , ((448, 511), "74C2B38820E2614D4AC42477185346D7"
                                       ++ "5EC3BB41DC9810610C5B745A1B423A3C"
                                       ++ "BF14A7E45C08C5E7C1CAE65B8839F030"
                                       ++ "A8E52500776B45EA65885322FC1B3A57" )
                          ]
    , testVector256 "Set 3, vector# 63"  ("3F404142434445464748494A4B4C4D4E"
                                       ++ "4F505152535455565758595A5B5C5D5E")
                                          "0000000000000000"
                           [ ((0, 63),    "AADBA970B29F5BB8522C3817E849E5D0"
                                       ++ "417863554D16D6FC42405CA5A826A82A"
                                       ++ "7F0ADD295D02DF3EB565E10CA1902E7E"
                                       ++ "E84CC977614F325AA0BCA298F64871C4" )
                           , ((192, 255), "23453B14E9067B2733C88A3137650D83"
                                       ++ "BF2EDEA3BD78D336765151C9DC15A534"
                                       ++ "5394C7B0E1B0DD3BEF7C7BBBB84AB0B5"
                                       ++ "7992446F8DD102F90B0D72728686EC17" )
                           , ((256, 319), "0291E9B6188CB3E43F98B576C9C114B4"
                                       ++ "E1165A39B33E32E7260D6767058C45B0"
                                       ++ "93717E09868B400557E750557417E7C7"
                                       ++ "F0DA6A8AB0179630023EEE17B0362575" )
                           , ((448, 511), "D98E6AF3B8A4BE5EE6CD4F067FDDE869"
                                       ++ "FA2569648498460C0B2E4A3A4652FB71"
                                       ++ "77D02D632BFEF2C3511F1D374AAADDE1"
                                       ++ "4542AC660114716E5CAF854AA5C2CF1A" )
                          ]
    , testVector256 "Set 3, vector# 72"  ("48494A4B4C4D4E4F5051525354555657"
                                       ++ "58595A5B5C5D5E5F6061626364656667")
                                          "0000000000000000"
                           [ ((0, 63),    "53AD3698A011F779AD71030F3EFBEBA0"
                                       ++ "A7EE3C55789681B1591EF33A7BE521ED"
                                       ++ "68FC36E58F53FFD6E1369B00E390E973"
                                       ++ "F656ACB097E0D603BE59A0B8F7975B98" )
                           , ((192, 255), "A04698274C6AC6EC03F66ED3F94C08B7"
                                       ++ "9FFDBF2A1610E6F5814905E73AD6D0D2"
                                       ++ "8164EEB8450D8ED0BB4B644761B43512"
                                       ++ "52DD5DDF00C31E3DABA0BC17691CCFDC" )
                           , ((256, 319), "B826C7F071E796D34E3BFFB3C96E76A1"
                                       ++ "209388392806947C7F19B86D379FA3AE"
                                       ++ "DFCD19EBF49803DACC6E577E5B97B0F6"
                                       ++ "D2036B6624D8196C96FCF02C865D30C1" )
                           , ((448, 511), "B505D41E2C207FA1C0A0E93413DDCFFC"
                                       ++ "9BECA8030AFFAC2466E56482DA0EF428"
                                       ++ "E63880B5021D3051F18679505A2B9D4F"
                                       ++ "9B2C5A2D271D276DE3F51DBEBA934436" )
                          ]
    , testVector256 "Set 3, vector# 81"  ("5152535455565758595A5B5C5D5E5F60"
                                       ++ "6162636465666768696A6B6C6D6E6F70")
                                          "0000000000000000"
                           [ ((0, 63),    "B2995CDC9255E4E6177398EECE05F338"
                                       ++ "BE14825E8025598C1B4B0B80013E5D4B"
                                       ++ "C195802ACF47326F309C58809E044CA0"
                                       ++ "2027CCE97D80F7AEBA6D0376C96BFD7A" )
                           , ((192, 255), "0B89114F6F4111D2C7C33B0CC3DE682F"
                                       ++ "932E9B060BD3D1E17801ADBF7F034819"
                                       ++ "2D1F77F99104BE2FE62AA14CAF17D0C2"
                                       ++ "35243B76D298C9CB51F7E5E02914027D" )
                           , ((256, 319), "A93BEF16E18FB3D34FD342AEAC4EC93F"
                                       ++ "474910948F5E25F20C3C6AF50FBFFD14"
                                       ++ "8B8272DF4AAE7400843AE11502D06196"
                                       ++ "59F3F2484D5D5659BC340039CAC03B20" )
                           , ((448, 511), "031AB90E5D0C95ED116B7D03EFDD3543"
                                       ++ "ACDA91FE89071680C1B025F305538F7E"
                                       ++ "7154BDF131351E68F0F0ADDD40FB5183"
                                       ++ "0DD7761114BB4BA9692BD72500E7B2A3" )
                          ]
    , testVector256 "Set 3, vector# 90"  ("5A5B5C5D5E5F60616263646566676869"
                                       ++ "6A6B6C6D6E6F70717273747576777879")
                                          "0000000000000000"
                           [ ((0, 63),    "447D16E09F139ADBFDBC742D248EC354"
                                       ++ "67F165D42937FBA97B816016613DE365"
                                       ++ "B0C23E4145CA71A3680B382CFF6D615C"
                                       ++ "E7B2B02AEE1B6CAE692E4D09B2B47CE4" )
                           , ((192, 255), "49DEBE1A89CE85C6BC52DCE9E80422D0"
                                       ++ "523FA99D29132F3B292B695EC641C0E3"
                                       ++ "C3C339414349F83BAAF6E534E426DA98"
                                       ++ "2BB80981B58401128A158AEB75FD48E7" )
                           , ((256, 319), "E661F70FC1DCB4437D4DE0C4F6540EFC"
                                       ++ "14D319CF67906DDBF41BA8FA8FD1B17E"
                                       ++ "A8452CCB67F4078A8CEB2953218F97C7"
                                       ++ "73850D1CB882656A6486C0D12F9324EE" )
                           , ((448, 511), "7916FA50772F5BCD5DBF87F6733466B7"
                                       ++ "E0DC28687A5AFDEE5BDFCA4A197E7B6D"
                                       ++ "82072AC49F2C7944519999FCE9438AF9"
                                       ++ "80EC5576BEF6454C43AEC151A488A405" )
                          ]
    , testVector256 "Set 3, vector# 99"  ("636465666768696A6B6C6D6E6F707172"
                                       ++ "737475767778797A7B7C7D7E7F808182")
                                          "0000000000000000"
                           [ ((0, 63),    "D356187B3A555932420B005EEA1703CB"
                                       ++ "6C568987D54316540561425C078A0BC1"
                                       ++ "6011BD3A1E88C62039608DDB65C35453"
                                       ++ "8E6E6BE417066D824B4CC3F4842D1B7D" )
                           , ((192, 255), "FC9DB2F6F1A10BB4690291F108119B07"
                                       ++ "C7D908E2A3C35BDEDF1F0B79041C04B9"
                                       ++ "1D63CE0D20459F3A99BF37AB195D907D"
                                       ++ "3EBF1C75C5B7272D29ED83C0ECAE915F" )
                           , ((256, 319), "2193BE6883F2B56B74312E46F422441C"
                                       ++ "C1A54EF08360C87F70AF598751E24F28"
                                       ++ "5E7A0C2F886147DFEC52B34466F3A598"
                                       ++ "8DDAF657AF45A452495F852233F3E312" )
                           , ((448, 511), "42822BF1D4BFD3122C2C842CE59BD9AD"
                                       ++ "4616D916AADBBADB1A7F710EED2F7211"
                                       ++ "653055D94569FA2BE4C2BA8B758E2956"
                                       ++ "2C7A3354074705A28891B5E66EB8A7D7" )
                          ]
    , testVector256 "Set 3, vector#108"  ("6C6D6E6F707172737475767778797A7B"
                                       ++ "7C7D7E7F808182838485868788898A8B")
                                          "0000000000000000"
                           [ ((0, 63),    "4C2EB1D4A9A84064F43082EAC25C741F"
                                       ++ "A49F2579FCB069A2B072B4D7EB704B38"
                                       ++ "E00DB35E0D9C2077E58B9403D73904B9"
                                       ++ "BDAF16A1C79A0A25B0B9BC06E49D2659" )
                           , ((192, 255), "DBB77843D3F626E1F577ED0AB0D90348"
                                       ++ "66237611BC25FEA9713D5D001D2FE59F"
                                       ++ "51A5C201D1EE6F7844BF231C34BB489A"
                                       ++ "CB3EA4434226248FDA91597AC400C8D2" )
                           , ((256, 319), "3AC1C77E12C7B3CD306743B805738AAA"
                                       ++ "8269B47132D1902ECEAD7EC403E2CE6F"
                                       ++ "D3EA6DFF1FE350995BAC330874EB0777"
                                       ++ "EA659488C3991432A1FF9CDE7ABB9D34" )
                           , ((448, 511), "FFC9E408A4521EFDA22B2D4C30F22781"
                                       ++ "D17CB1C709C4ECB2FD03ABEF56B4DD98"
                                       ++ "6379C068662A5CBC01053A0A7B3D1A0E"
                                       ++ "9B9AB81EEB8F57EDED3BE1EE75ED340B" )
                          ]
    , testVector256 "Set 3, vector#117"  ("75767778797A7B7C7D7E7F8081828384"
                                       ++ "85868788898A8B8C8D8E8F9091929394")
                                          "0000000000000000"
                           [ ((0, 63),    "B36D9BB49A62689A751CF5C971A15F70"
                                       ++ "439E56DC516F15F958369E3DA2500EC4"
                                       ++ "D51CE469B050037570D03B0948D9FF82"
                                       ++ "F2AD1B1D65FA5D782CAE515E03BA6A60" )
                           , ((192, 255), "0A4DE80091F11609F0AE9BE3AA9BE969"
                                       ++ "9AA1C0BDEE5C1DE5C00C36C642D7FF87"
                                       ++ "2195871708F2A2325DE93F81462E7305"
                                       ++ "4CECEFA7C1906CDAE88F874135D5B95D" )
                           , ((256, 319), "F69916317394BF360EB6E726751B7050"
                                       ++ "96C5BF1317554006E4E832123D7E43CE"
                                       ++ "74A06499BF685BB0AAC8E19C41C75B1C"
                                       ++ "840FD9375F656AD2B1377B5A0B26289A" )
                           , ((448, 511), "5A49B471376394B09890CA0A5A72410A"
                                       ++ "B34ED9B829B127FB5677026E1BFC75B4"
                                       ++ "AFE9DBF53B5C1B4D8BEB5CEDB678D697"
                                       ++ "FE56DACBA9D6DEA9C57CD8243153755A" )
                          ]
    , testVector256 "Set 3, vector#126"  ("7E7F808182838485868788898A8B8C8D"
                                       ++ "8E8F909192939495969798999A9B9C9D")
                                          "0000000000000000"
                           [ ((0, 63),    "4E7DB2320A4A7717959C27182A53072B"
                                       ++ "9D18874644B42B319963B5512340AA4D"
                                       ++ "C7088FE4803EE59CC25E77AC29D13E72"
                                       ++ "20654487F4A3BF2D39C073C7D231DB17" )
                           , ((192, 255), "58A4B8F161BE5C1AC1573FB95C216AAE"
                                       ++ "ADBF17205072225CD2236439A574B40A"
                                       ++ "2AD76749E37AAEC60B52D79F5DA5459F"
                                       ++ "094244FDE783122FACE929D94E914A87" )
                           , ((256, 319), "BE41A549607DA00691D0C3734D1F9CF7"
                                       ++ "1A0D21056E50BC89F29135989432FDB5"
                                       ++ "C2340BFF6D181946BACD49D4B28A5104"
                                       ++ "97990B241CE021280159DFAAC44DA45C" )
                           , ((448, 511), "E7CEFE15DADB07044C730CE7650E4124"
                                       ++ "687B7781C85C472EF6D3DD6C7150B050"
                                       ++ "001904552B59778F2BAEA8C0CA29900F"
                                       ++ "0470F14CCED15E2D83FB1A06A0C57C7E" )
                          ]
    , testVector256 "Set 3, vector#135"  ("8788898A8B8C8D8E8F90919293949596"
                                       ++ "9798999A9B9C9D9E9FA0A1A2A3A4A5A6")
                                          "0000000000000000"
                           [ ((0, 63),    "EE17A6C5E4275B77E5CE6B0549B556A6"
                                       ++ "C3B98B508CC370E5FA9C4EA928F7B516"
                                       ++ "D8C481B89E3B6BE41F964EE23F226A97"
                                       ++ "E13F0B1D7F3C3FBBFF2E49A9A9B2A87F" )
                           , ((192, 255), "1246C91147270CA53D2CEACA1D11D00B"
                                       ++ "F83BB8F1C893E6F10118807D71021972"
                                       ++ "586592F9935827B03EA663B7CF032AA7"
                                       ++ "ED9F1F9EE15409B18E08D12F4880E162" )
                           , ((256, 319), "6B6AC56A7E4C7636D6589886D8D27462"
                                       ++ "41BACAF2A1C102C5D0DE1603E4C7A92B"
                                       ++ "42F609BCB73BC5BFC0927EF075C72656"
                                       ++ "7018B47870365138EE821345C958F917" )
                           , ((448, 511), "DA438732BA03CBB9AFFF4B796A0B4482"
                                       ++ "EA5880D7C3B02E2BE135B81D63DF351E"
                                       ++ "EECEFA571731184CD5CB7EEA0A1D1626"
                                       ++ "83BA706373017EE078B8068B14953FBF" )
                          ]
    , testVector256 "Set 3, vector#144"  ("909192939495969798999A9B9C9D9E9F"
                                       ++ "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
                                          "0000000000000000"
                           [ ((0, 63),    "14530F67317B09CB008EA4FD08813F80"
                                       ++ "4AC63D6B1D595D21E244E11AA4F153E1"
                                       ++ "256DF77976F713B4F7DD1DF64E7016BB"
                                       ++ "F9460A1A7CC7F3E9D28D8D19A69EB0B4" )
                           , ((192, 255), "6C025A7A0A9F32AE768D35C56231AFFF"
                                       ++ "5E9A283260E54F442D1F3263A837545C"
                                       ++ "234F7701D1A5B568DDA76A5D596F532C"
                                       ++ "4F950425A2F79CD74203CCBB27293020" )
                           , ((256, 319), "CA585389DDA8D79B73CA2C64B476C776"
                                       ++ "0DC029271B359EB10D09B90FEF816E96"
                                       ++ "432CCEDFB51322F7AEA6DEB896E048FA"
                                       ++ "2AAD234F89C45FC25967DF99955B1234" )
                           , ((448, 511), "7DECE5C4BA2E08A2A61A37D9DD56BC89"
                                       ++ "2E141874A572AE4342067CBD4E080933"
                                       ++ "1851640E5D6EF48F73A4A638C74471C1"
                                       ++ "85E731136BAC231B0803A66A4CDB6A4C" )
                          ]
    , testVector256 "Set 3, vector#153"  ("999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8"
                                       ++ "A9AAABACADAEAFB0B1B2B3B4B5B6B7B8")
                                          "0000000000000000"
                           [ ((0, 63),    "9B05907B8F2EE3E831D9A0BE6203DBED"
                                       ++ "012C381B7E3225B52282B9D0BA5A5A6A"
                                       ++ "A367F7C553177557B87FFAA73C59E123"
                                       ++ "B8B2F069B6C0F6DF25CC0A340CD2550D" )
                           , ((192, 255), "4274D6C7996E9E605D378A52CB5AECCC"
                                       ++ "E6EF862FC0F40091C79FDC93DE2B7CF8"
                                       ++ "4B484FC874687BE243965F92080444D2"
                                       ++ "206123C6815E9A497610283D79EB8FA9" )
                           , ((256, 319), "B9EBAF94F5CD2CCDAA2F8804E586DE09"
                                       ++ "98A5E2E79D9C2E9F6267A16B314C3748"
                                       ++ "07E7DD80A3115D2F64F1A7B6AF174AD6"
                                       ++ "8EA04962D48C7F0BCA72D9CDA9945FB1" )
                           , ((448, 511), "A08547DA215E1372CED1AC1192431AF3"
                                       ++ "52B670CE9FF5F1F3A598CB17961D7780"
                                       ++ "F1D08A6C69BF2EF73BB54DAC8308D320"
                                       ++ "66CB8132DE497FDD9BB54739A54A57AC" )
                          ]
    , testVector256 "Set 3, vector#162"  ("A2A3A4A5A6A7A8A9AAABACADAEAFB0B1"
                                       ++ "B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1")
                                          "0000000000000000"
                           [ ((0, 63),    "7D0FF0DCB7CAAC90E548E24BEEA22D10"
                                       ++ "1C927E0A9BD559BC32BA70B346659F41"
                                       ++ "8FD9E36202D3AF35CB836F1BD15087DE"
                                       ++ "0D01FFF0BD42BC24B01A65CAD6F38E2C" )
                           , ((192, 255), "12E246BA025A6174789C631646D092A8"
                                       ++ "865094571FF71BC28A38BEACEB08A822"
                                       ++ "72441DE97C1F273A9AE185B1F05B2953"
                                       ++ "EC37C940EE4C3AB5C901FF563563CCC9" )
                           , ((256, 319), "2B48A7B5979BD5D27E841D2A6ED203D7"
                                       ++ "9126471DB9201444D07FCEA31A66D22F"
                                       ++ "DC65636F451B8D51365639CE2F5090B8"
                                       ++ "D08E14FE955580CB3692F4A35410D9BA" )
                           , ((448, 511), "A94E650CCC1ADEE62D2BAC9AA8969BA1"
                                       ++ "911429B6B9287E2E8A553752EDDF6F82"
                                       ++ "132FA5620E1F4F671EDF9C2EF1B76DB1"
                                       ++ "CE63A8A61EDF905A8D5D195D8EE7A116" )
                          ]
    , testVector256 "Set 3, vector#171"  ("ABACADAEAFB0B1B2B3B4B5B6B7B8B9BA"
                                       ++ "BBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CA")
                                          "0000000000000000"
                           [ ((0, 63),    "F943B21C04A85C22ED1FC5BFBACAAF93"
                                       ++ "2CB889EF7CD4472089B16B6DDA5C72E9"
                                       ++ "A8F11B66CFC7677D72FB8908018B2A32"
                                       ++ "F6B37A2AC811665D8266841199C066AE" )
                           , ((192, 255), "E877CA4C8570A4A0CF06FECCCF0430BB"
                                       ++ "C63077B80518C4BFEC10BA18ABB08C0B"
                                       ++ "3FD72D94EED86F1A9A38385AD4395A96"
                                       ++ "7ABB10B245D71680E50C2918CB5AE210" )
                           , ((256, 319), "89B67848C1661AFE6D54D7B7A92EB3FF"
                                       ++ "AB5D4E1438B6BEB9E51DE6733F08A71F"
                                       ++ "F16B676851ADD55712C5EE91B3F89381"
                                       ++ "0352A3C0DC7093FCC6D11810C475F472" )
                           , ((448, 511), "14ABC36FB047EB4137390D3AA3486407"
                                       ++ "7400CDF9AC001025BA6F45BEDD460ECD"
                                       ++ "2FD4C16064F5579C50ACC64361EE9470"
                                       ++ "468B39F5CABCF366E0AE7DEA4EB1FEB1" )
                          ]
    , testVector256 "Set 3, vector#180"  ("B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3"
                                       ++ "C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3")
                                          "0000000000000000"
                           [ ((0, 63),    "5F76E49A712A9B36D646FDB1355FA862"
                                       ++ "DE02BDC06E9AA4DF8DC0749102ADB071"
                                       ++ "D575101D0CA6E36034EE3A039CF5239B"
                                       ++ "817466A88DE350081D91090D79842DF5" )
                           , ((192, 255), "48AEECB9BA29A1B52B2A5F58597980CF"
                                       ++ "2B5A31CD6DB97B98A4DB560500705ED7"
                                       ++ "0BF7D9946DF6B2D26C77E2BC3152F23C"
                                       ++ "2302F08ADE124F97E9E45F2894832434" )
                           , ((256, 319), "BD9BFA707093FD92BE49E0B0FD0A9E89"
                                       ++ "0AFD92AC6A50375173CE0C966C9D9A87"
                                       ++ "E2B538445E697EA193BD33D60DC9F107"
                                       ++ "1784CDA56C8AAD2BC67E17C9F5BDBAF8" )
                           , ((448, 511), "1477E6B19CA394B91496C5C1E1EFE3D4"
                                       ++ "68D157B035C87A4667F6559F56C84ABF"
                                       ++ "3CE27D85D85784C40081EA064835904D"
                                       ++ "AE34A9277900B6F2F0B67F44B6B41776" )
                          ]
    , testVector256 "Set 3, vector#189"  ("BDBEBFC0C1C2C3C4C5C6C7C8C9CACBCC"
                                       ++ "CDCECFD0D1D2D3D4D5D6D7D8D9DADBDC")
                                          "0000000000000000"
                           [ ((0, 63),    "1D8D3CB0B17972779FBD8339BDBC5D0C"
                                       ++ "4178C943381AFA6FA974FF792C78B4BB"
                                       ++ "5E0D8A2D2F9988C01F0FF7CE8AD310B6"
                                       ++ "6FA3B8D8CB507E507C4516BC9E7603B6" )
                           , ((192, 255), "F32D0691B1832478889516518C441ADB"
                                       ++ "8F0FE2165B15043756BB37928EBCA33F"
                                       ++ "9C166A5907F7F85CCF45CE6BFB68E725"
                                       ++ "748FA39528149A0E96B0B6C656854F88" )
                           , ((256, 319), "66A7226EA4CF4DB203592F0C678BA8D2"
                                       ++ "99F26E212F2874681E29426A579469B2"
                                       ++ "CA747B8620E7E48A7E77D50E5C45FF62"
                                       ++ "A733D6052B2FB4AAB4AC782539193A76" )
                           , ((448, 511), "25CCCD9E6FF25D8D6525E621BC376F6A"
                                       ++ "F73C749E80213260F1418B0C191B1F24"
                                       ++ "C1922DAD397EFA6062BBE9E3612D35D5"
                                       ++ "30F49C5D9D4F11E4CB2B3A4E66731FA8" )
                          ]
    , testVector256 "Set 3, vector#198"  ("C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5"
                                       ++ "D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5")
                                          "0000000000000000"
                           [ ((0, 63),    "9D2EB0E9A93A0EF9F8ABCE0916C06EEB"
                                       ++ "E9C8EBB52A8112CD352A8E2E4EE84DFD"
                                       ++ "44B7C8251D0D1A36EA69CEB8C595D527"
                                       ++ "DA0EF26A2C5A5F443DC3040C6BF2DA49" )
                           , ((192, 255), "A86842C08DA057352B70FB63EBD1516F"
                                       ++ "D56E7BB389BBBB22F8EDE940DC7036CF"
                                       ++ "E10104AB81A51F23CFE35CCCC07BF50D"
                                       ++ "40A2438F3B3AEAB62953406A9E7D7BF3" )
                           , ((256, 319), "9EE5EE22FFEDB13C11A81B0E5EC82DB6"
                                       ++ "303F22A62F0FD0574CE7007AF1EA2FCC"
                                       ++ "23D9C4196EBE897AB0D00371429F518E"
                                       ++ "C150063EAE314EE72EFADB1AA7714AC6" )
                           , ((448, 511), "125ACD159548C79FCC93BFEC7B832C5D"
                                       ++ "387AFD85A0537BB6A49A8C3F4673306B"
                                       ++ "D76E17AC601629E00AB5AFF62B269491"
                                       ++ "AD996A624C6B1888BF13785AD63DEC7C" )
                          ]
    , testVector256 "Set 3, vector#207"  ("CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE"
                                       ++ "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEE")
                                          "0000000000000000"
                           [ ((0, 63),    "1D99BD420A9EBE17CF6144EEBE46A4B5"
                                       ++ "D8CE913F571DCEDEE6C6E3CFA27572F5"
                                       ++ "9983D4B2CADC292A956983AF7250CA81"
                                       ++ "A23A9EDA42417CC150597891045FF321" )
                           , ((192, 255), "D53AB2E60871F42D10E6747FE358E562"
                                       ++ "14D7CE3E7BA38E51354C801B72E5D515"
                                       ++ "DD805F8FDBA9F1BC81C5926DBE8CDBD2"
                                       ++ "3B006714CC8D550671036F6FD2991825" )
                           , ((256, 319), "FD97553220FB51132C33EBDA78606A24"
                                       ++ "5C5E3578A69754BF4FC11D6242605160"
                                       ++ "B4085DFDFC3D11505F72DC15CC16C683"
                                       ++ "37798E0DABD37C67B2E8912E498EA940" )
                           , ((448, 511), "A2D9199683D73F01DDD77BD46CD5BCEF"
                                       ++ "37CD9D4ECBA40B6C51446DCC68BCAD18"
                                       ++ "9FBEFEFC3D82131ECF98263299DC0CA9"
                                       ++ "1DD349E4DD348A88B2E3D7AA2D20CC13" )
                          ]
    , testVector256 "Set 3, vector#216"  ("D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7"
                                       ++ "E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7")
                                          "0000000000000000"
                           [ ((0, 63),    "B9751AF24FCF14907948F7AD36E2649A"
                                       ++ "9A07B637F84D34E961EE82B7C33A9CC3"
                                       ++ "7B96DA6A956AFF4A629546C422802767"
                                       ++ "AD9F24BB2E79F09FCD43775FAC965123" )
                           , ((192, 255), "6C4CB6AD15DDCE11F1BF68FFF1376E0F"
                                       ++ "4CE35ABCE777F4AB1D6906D09184689D"
                                       ++ "B697D1CFFAF46C5B85AD9F21CFF0D756"
                                       ++ "3DF67CF86D4199FA055F4BE18AFA34C2" )
                           , ((256, 319), "35F4A1BBB9DA8476A82367A5607C72A0"
                                       ++ "C273A8D1F94DC4D62FDB2FA303858678"
                                       ++ "FABCD6C6EBA64849640BFB6FE4ADB340"
                                       ++ "28FAE26F802EA0ECE37D2AC2F2560CE8" )
                           , ((448, 511), "3D208E3CFAF58AF11BCC527F948A3B75"
                                       ++ "E1751A28A76CBFE94204783820AD7FEE"
                                       ++ "7C98B318EDA2DC87111D18978CEE0C0C"
                                       ++ "E39F1469E7CB3EEEDBD6BF30DA68DF34" )
                          ]
    , testVector256 "Set 3, vector#225"  ("E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0"
                                       ++ "F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF00")
                                          "0000000000000000"
                           [ ((0, 63),    "EA444200CDE137A48DD3728CFC0FE82A"
                                       ++ "1CD6F0F412C0343639052B6471F8321C"
                                       ++ "3C9A38986A5F882A26ABCFB342D3FF50"
                                       ++ "4E2EBF01D8CDA2408AE1A9023F4D64CA" )
                           , ((192, 255), "5C20B3CECA032C29E7B8118BB8B946F9"
                                       ++ "90A9DD8895D9D7FE620727087DB8C6E9"
                                       ++ "6973741552A24E8C3B9EC81FA2B06E5F"
                                       ++ "F4283201639C83CC0C6AF8AA20FBDDD9" )
                           , ((256, 319), "4DB2FF5167737BB90AD337FE16C10BD9"
                                       ++ "E4D2B8D6FBD172F5448D099D24FEAEA9"
                                       ++ "B30224AB670781C667292D04C76EFEC2"
                                       ++ "476B2D33ADA7A7132677E4B8270C68CD" )
                           , ((448, 511), "5AB9F03158EA17B1D845CDC688C3BB0F"
                                       ++ "F1AC5CEAA2F16DB3178223D1471D0191"
                                       ++ "0E9D5BB3C6D0C9CC652C0ACF527B4F44"
                                       ++ "94B0DE521164493800E132B272A42A22" )
                          ]
    , testVector256 "Set 3, vector#234"  ("EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9"
                                       ++ "FAFBFCFDFEFF00010203040506070809")
                                          "0000000000000000"
                           [ ((0, 63),    "99A8CCEC6C5B2A0B6E336CB20652241C"
                                       ++ "32B24D34ACC0457EF679178EDE7CF805"
                                       ++ "805A9305C7C49909683BD1A803327817"
                                       ++ "627CA46FE8B929B6DF0012BD864183BE" )
                           , ((192, 255), "2D226C11F47B3C0CCD0959B61F59D5CC"
                                       ++ "30FCEF6DBB8CBB3DCC1CC25204FCD449"
                                       ++ "8C37426A63BEA3282B1A8A0D60E13EB2"
                                       ++ "FE59241A9F6AF426689866EDC769E1E6" )
                           , ((256, 319), "482FE1C128A15C1123B5655ED546DF01"
                                       ++ "4CE0C455DBF5D3A13D9CD4F0E2D1DAB9"
                                       ++ "F12FB68C544261D7F88EAC1C6CBF993F"
                                       ++ "BBB8E0AA8510BFF8E73835A1E86EADBB" )
                           , ((448, 511), "0597188A1C19255769BE1C210399AD17"
                                       ++ "2EB46C52F92FD541DF2EAD71B1FF8EA7"
                                       ++ "ADD380EC71A5FD7ADB5181EADD1825EC"
                                       ++ "02779A4509BE5832708CA2836C1693A5" )
                          ]
    , testVector256 "Set 3, vector#243"  ("F3F4F5F6F7F8F9FAFBFCFDFEFF000102"
                                       ++ "030405060708090A0B0C0D0E0F101112")
                                          "0000000000000000"
                           [ ((0, 63),    "B4C0AFA503BE7FC29A62058166D56F8F"
                                       ++ "5D27DC246F75B9AD8760C8C39DFD8749"
                                       ++ "2D3B76D5D9637F009EADA14458A52DFB"
                                       ++ "09815337E72672681DDDC24633750D83" )
                           , ((192, 255), "DBBA0683DF48C335A9802EEF02522563"
                                       ++ "54C9F763C3FDE19131A6BB7B85040624"
                                       ++ "B1D6CD4BF66D16F7482236C8602A6D58"
                                       ++ "505EEDCCA0B77AED574AB583115124B9" )
                           , ((256, 319), "F0C5F98BAE05E019764EF6B65E0694A9"
                                       ++ "04CB9EC9C10C297B1AB1A6052365BB78"
                                       ++ "E55D3C6CB9F06184BA7D425A92E7E987"
                                       ++ "757FC5D9AFD7082418DD64125CA6F2B6" )
                           , ((448, 511), "5A5FB5C8F0AFEA471F0318A4A2792F7A"
                                       ++ "A5C67B6D6E0F0DDB79961C34E3A564BA"
                                       ++ "2EECE78D9AFF45E510FEAB1030B102D3"
                                       ++ "9DFCECB77F5798F7D2793C0AB09C7A04" )
                          ]
    , testVector256 "Set 3, vector#252"  ("FCFDFEFF000102030405060708090A0B"
                                       ++ "0C0D0E0F101112131415161718191A1B")
                                          "0000000000000000"
                           [ ((0, 63),    "2064790538ACDF1DE3852C465070D962"
                                       ++ "FE2993BDD20C96DED5B2E5FA33283374"
                                       ++ "2A6B03966D47F8874D39C501ECFE0045"
                                       ++ "725C463530967ED1499097906B9775C3" )
                           , ((192, 255), "9F880124435347E31FDF6EF96981FAB3"
                                       ++ "1A912D0B70210CBED6DDC9813521CCE2"
                                       ++ "B5C2B80193A59DCD933026D262E8EC74"
                                       ++ "F5880028FBB06166E0A304453A3A54BB" )
                           , ((256, 319), "8A3F922FCDE48CE6C2E324EAA639DECC"
                                       ++ "E7257A25C420A2435BBA98740DF6C92A"
                                       ++ "8FA18F1D4E67C5F75F314219BB769685"
                                       ++ "A0C028D115321D10D58B46E5D58ABB4E" )
                           , ((448, 511), "905C86F2F2C1E0454963E21D7498E8F4"
                                       ++ "67ECF23F8B02671F57584322E9952223"
                                       ++ "58D4FD541714BF12EFB189ACEA624AFF"
                                       ++ "2D55B252974D39D8598E8A066536ACB2" )
                          ]
    , testVector256 "Set 4, vector#  0"  ("0053A6F94C9FF24598EB3E91E4378ADD"
                                       ++ "3083D6297CCF2275C81B6EC11467BA0D")
                                          "0000000000000000"
                           [ ((0, 63),    "F9D2DC274BB55AEFC2A0D9F8A982830F"
                                       ++ "6916122BC0A6870F991C6ED8D00D2F85"
                                       ++ "94E3151DE4C5A19A9A06FBC191C87BF0"
                                       ++ "39ADF971314BAF6D02337080F2DAE5CE" )
                           , ((65472, 65535), "05BDA8EE240BA6DC53A42C14C17F620F"
                                       ++ "6FA799A6BC88775E04EEF427B4B9DE5A"
                                       ++ "5349327FCADA077F385BA321DB4B3939"
                                       ++ "C0F49EA99801790B0FD32986AFC41B85" )
                           , ((65536, 65599), "FED5279620FBCBDD3C3980B11FCE4787"
                                       ++ "E6F9F97772BEAAD0EF215FDCD0B3A16F"
                                       ++ "BB56D72AFD5FD52E6A584BF840914168"
                                       ++ "D04A594FFDDA959A63EB4CF42694F03F" )
                           , ((131008, 131071), "F161DCE8FA4CF80F8143DDB21FA1BFA3"
                                       ++ "1CA4DC0A412233EDE80EF72DAA1B8039"
                                       ++ "4BCE3875CA1E1E195D58BC3197F803A8"
                                       ++ "9C433A59A0718C1A009BCB4DA2AC1778" )
                          ]
    , testVector256 "Set 4, vector#  1"  ("0558ABFE51A4F74A9DF04396E93C8FE2"
                                       ++ "3588DB2E81D4277ACD2073C6196CBF12")
                                          "0000000000000000"
                           [ ((0, 63),    "2F634849A4EDC206CE3E3F89949DF4E6"
                                       ++ "EA9A0E3EE87F0AB108C4D3B789ACE673"
                                       ++ "07AC8C54F07F30BAD9640B7F6EDEEC9D"
                                       ++ "B15E51599EB15E1CA94739FEA5F1E3D7" )
                           , ((65472, 65535), "EB2B0FD63C7EEEAA5A4D712EEEFC0A7E"
                                       ++ "214BEB04D3FDA19C32250949868216D3"
                                       ++ "A659B312E13EC66C5832E970F9C91FF9"
                                       ++ "4F7463439A9827ECCA52248D3CC604CD" )
                           , ((65536, 65599), "425E0DF93A3DE6B22E0871EB4E435691"
                                       ++ "D77B5C471228DE302A79001F89F7E77D"
                                       ++ "837C5CA0177B2206568EDC2EB0F169D5"
                                       ++ "6B414B9DCCDC928659B4BE1E0DEDFF73" )
                           , ((131008, 131071), "6AA3D6938B6B54B4CB8D2885274A991B"
                                       ++ "4A0D5CCF35D981953EC64452FACC8640"
                                       ++ "B5ACFA39A372E38BE4E10EE68E7F1B50"
                                       ++ "5A5660CDFBAE8DCBFCC9A3847BBB6BA4" )
                          ]
    , testVector256 "Set 4, vector#  2"  ("0A5DB00356A9FC4FA2F5489BEE4194E7"
                                       ++ "3A8DE03386D92C7FD22578CB1E71C417")
                                          "0000000000000000"
                           [ ((0, 63),    "0A8BBD088ABADC4D57D3389E32175878"
                                       ++ "125BD89DE7E9D05DBF29B753F5F0C2CB"
                                       ++ "F0EEF9333526E9308A114E06EB9564EB"
                                       ++ "35C28EA93C17BEF0466748079A355B9C" )
                           , ((65472, 65535), "F47FDFF047F0303F6CCE2510FA2475F0"
                                       ++ "7784D5F0FBD63D1746BD8CE4BB02802C"
                                       ++ "3052A375D7DE75D439174E7B19CEBA3B"
                                       ++ "9546DB027F14FFDB9EF542D5768CE5A7" )
                           , ((65536, 65599), "40FEC0EE1697D63CB04299A17C446DE0"
                                       ++ "6B3407D10C6DD2143DFA24EB7362D09A"
                                       ++ "6857C6AA83A191D65B05EBBBC8133D12"
                                       ++ "2BDE75900C86FCD8785EECE48659C3B0" )
                           , ((131008, 131071), "7820087794D46993E984536E7B74C615"
                                       ++ "67AB34C6C0A90090DB080E6EB79532FB"
                                       ++ "414CD1145A781A2C55519A3E3AD19FA6"
                                       ++ "D78790313EBE19A86F61068E4C8E508D" )
                          ]
    , testVector256 "Set 4, vector#  3"  ("0F62B5085BAE0154A7FA4DA0F34699EC"
                                       ++ "3F92E5388BDE3184D72A7DD02376C91C")
                                          "0000000000000000"
                           [ ((0, 63),    "4A671A2AE75DB7555BEA5995DC53AF8D"
                                       ++ "C1E8776AF917A3AB2CA9827BCED53DA7"
                                       ++ "00B779820F17294751A2C37EF5CCCFE9"
                                       ++ "7BF7481E85AFC9ECAE431B7CF05F6153" )
                           , ((65472, 65535), "15C415BE73C12230AC9505B92B2B1273"
                                       ++ "7F6FB2FAAF9C51F22ECCB8CBED36A27A"
                                       ++ "1E0738E1252D26E8E5E5651FE8AA02CC"
                                       ++ "9887D141A7CBAE80F01BE09B314005BB" )
                           , ((65536, 65599), "1C48158413F5EC5E64D2FA4786D91D27"
                                       ++ "27DF6BECD614F6AE745CF2B6F35CD824"
                                       ++ "3E5F1C440BEDE01E6C8A1145F2AB77FA"
                                       ++ "24D634DE88F955D4F830D4A548A926D0" )
                           , ((131008, 131071), "A9BE2FB00C8BD01054153F77EC0C633C"
                                       ++ "E8DF7F78E994907B9F387FF090CB3B95"
                                       ++ "4271FEADF50C9084106F4285FF4F534D"
                                       ++ "AEC130AAE287D47033179BBAEEB36CE6" )
                          ]
    , testVector256 "Set 5, vector#  0"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "8000000000000000"
                           [ ((0, 63),    "2ABA3DC45B4947007B14C851CD694456"
                                       ++ "B303AD59A465662803006705673D6C3E"
                                       ++ "29F1D3510DFC0405463C03414E0E07E3"
                                       ++ "59F1F1816C68B2434A19D3EEE0464873" )
                           , ((192, 255), "EFF0C107DCA563B5C0048EB488B40341"
                                       ++ "ED34052790475CD204A947EB480F3D75"
                                       ++ "3EF5347CEBB0A21F25B6CC8DE6B48906"
                                       ++ "E604F554A6B01B23791F95C4A93A4717" )
                           , ((256, 319), "E3393E1599863B52DE8C52CF26C752FB"
                                       ++ "473B74A34D6D9FE31E9CA8DD6292522F"
                                       ++ "13EB456C5BE9E5432C06E1BA3965D454"
                                       ++ "48936BC98376BF903969F049347EA05D" )
                           , ((448, 511), "FC4B2EF3B6B3815C99A437F16BDB06C5"
                                       ++ "B948692786081D91C48CC7B072ABB901"
                                       ++ "C0491CC6900F2FEA217BFFC70C43EDD6"
                                       ++ "65E3E020B59AAA43868E9949FBB9AE22" )
                          ]
    , testVector256 "Set 5, vector#  9"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0040000000000000"
                           [ ((0, 63),    "F28343BCF4C946FC95DCAAED9DA10B27"
                                       ++ "7E573FC8EBC8CEE246FDDC533D29C2EA"
                                       ++ "05451ED9A821C4161EE0AFA32EC0FCA0"
                                       ++ "DAD124B702DA9248B3D2AA64489C9D26" )
                           , ((192, 255), "C65F799168D6B229D0281309526B746C"
                                       ++ "490D3EDC0F6408A04339275FCE04BDF4"
                                       ++ "656AB5868495C32D238FDB97869A9332"
                                       ++ "E09CB7BE8031D38B8F565FB5469C8459" )
                           , ((256, 319), "03E48FD41282FCD62C7217ED64153E55"
                                       ++ "B558F82A613245C3D8A885542346AA39"
                                       ++ "27DE9734C0581338C3DE5DB443EC4227"
                                       ++ "E3F82677D259D2D42601D187C79BF87A" )
                           , ((448, 511), "551F95AD9751E4F4BACE7FD48B6A3C67"
                                       ++ "E86C4B1E5B747BA60377B07FE8365E09"
                                       ++ "F8973085F8A6086FC56BD88168D8C561"
                                       ++ "8B01B159EF29F658C85FD117925D46E0" )
                          ]
    , testVector256 "Set 5, vector# 18"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000200000000000"
                           [ ((0, 63),    "621F3014E0ADC8022868C3D9070BC49E"
                                       ++ "48BC6B504AFF11CB17957F0EBFB7612F"
                                       ++ "7FCB67C60A2FBD7A4BD7C312E8F50AF3"
                                       ++ "CA7520821D73DB47189DAD557C436DDC" )
                           , ((192, 255), "42C8DFE869C90018825E2037BB5E2EBB"
                                       ++ "C4A4A42660AFEA8A2E385AFBBC63EF30"
                                       ++ "98D052FF4A52ED12107EE71C1AEC271E"
                                       ++ "6870538FCEAA1191B4224A6FFDCE5327" )
                           , ((256, 319), "4214DA4FAF0DF7FC2955D81403C9D49E"
                                       ++ "E87116B1975C5823E28D9A08C5B1189D"
                                       ++ "C52BCBEF065B637F1870980CB778B75A"
                                       ++ "DDA41613F5F4728AD8D8D189FBF0E76D" )
                           , ((448, 511), "4CA854257ECE95E67383FC8665C3A823"
                                       ++ "8B87255F815CA4DEC2D57DB72924C60C"
                                       ++ "B20A7EE40C559406AAAB25BE5F47184D"
                                       ++ "D187ED7EA191133F3000CB88DCBAC433" )
                          ]
    , testVector256 "Set 5, vector# 27"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000001000000000"
                           [ ((0, 63),    "D2DB1A5CF1C1ACDBE81A7A4340EF5343"
                                       ++ "5E7F4B1A50523F8D283DCF851D696E60"
                                       ++ "F2DE7456181B8410D462BA6050F061F2"
                                       ++ "1C787FC12434AF58BF2C59CA9077F3B0" )
                           , ((192, 255), "6CE020B3E83765A11F9AE157AD2D07D1"
                                       ++ "EA4E9FBBF386C83FEF54319746E5F997"
                                       ++ "D35BE9F73B99772DA97054FF07301314"
                                       ++ "3FF9E5B47C61966D8525F17265F48D08" )
                           , ((256, 319), "FFEAB16EEA5C43BFD08D2591F9A40293"
                                       ++ "24CDDC83A840B2C136B7CE99AF3A66CB"
                                       ++ "3084E4E2CA6F44AC5CEAF7A1157BE267"
                                       ++ "3DF688B43BD51B9A8444CE194E3CA7F2" )
                           , ((448, 511), "0D3873FD47A7B3400115C40574469D21"
                                       ++ "5BCE0679ED5CF9E374E473B4427DE498"
                                       ++ "5804DD75151D72EE367A3F066E641B7F"
                                       ++ "5CF28A67215B74DD80EB3FC02E12A308" )
                          ]
    , testVector256 "Set 5, vector# 36"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000008000000"
                           [ ((0, 63),    "22E129373F7589D9EAFFF18DEA63432E"
                                       ++ "38D0245BAE221D3635BEE176760552B8"
                                       ++ "9B6BC49CFEB7D9A5B358963C488ED8FA"
                                       ++ "D01F1C72307CADEEF9C20273FB5D6775" )
                           , ((192, 255), "6E6FFCB8B324EE4FF55E64449B2A356B"
                                       ++ "D53D8AB7747DFFC0B3D044E0BE1A736B"
                                       ++ "4AB2109624600FE8CA7E6949A4DF82AC"
                                       ++ "A5C96D039F78B67767A1B66FAB0EF24B" )
                           , ((256, 319), "C3DF823DBA0F84D70E425D0C2C88DCE3"
                                       ++ "CAEC3ACCA435B5A2832BE2E0F0AA46AD"
                                       ++ "3F288AFE49BE5C345DC65445D26993F5"
                                       ++ "1E3F46E0C1B02B5AEDF73D68336AA04F" )
                           , ((448, 511), "443B0FDC4F8365AB93A07682EBCA7B92"
                                       ++ "42259A26DAB3574B2E562CCABDB25633"
                                       ++ "96F331146347C26D5DB49C87054642F8"
                                       ++ "60FC1A0B87468ED0B5CB9C30D72EA8F7" )
                          ]
    , testVector256 "Set 5, vector# 45"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000040000"
                           [ ((0, 63),    "DC302570A4D1C44F31D9FA55C7712B11"
                                       ++ "AE770BFAA3F8631DFF924BCF00A09C90"
                                       ++ "6571B024CE5264215E516D73416BF3E3"
                                       ++ "CE373CAE669DB1A057EFD7EB184243B6" )
                           , ((192, 255), "A52427068F8048FC5E3E6E94A1A616CD"
                                       ++ "11F5A9ED4F8899F780F67836EEC4FADB"
                                       ++ "B19C183C6946541F182F224104DF9444"
                                       ++ "66D96A6CE7F2EFE723807A8738950AD9" )
                           , ((256, 319), "D1410A14DFA3DA5C9BDF18A34476F7C0"
                                       ++ "D7A8373331741ED62682C555EA8B62A8"
                                       ++ "1EDB10DB9479BAF2CD532CFB18357A92"
                                       ++ "FF90897315F69CEE526DE31329CFA06B" )
                           , ((448, 511), "9CA44AF188E42090F9969FB5F771C987"
                                       ++ "557912B83261760EE80A809F7E398A66"
                                       ++ "D56049FFDFFBD3E16633537B84AFB38E"
                                       ++ "564B717A0C26EBFEE907B8EF7FDA31F0" )
                          ]
    , testVector256 "Set 5, vector# 54"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000200"
                           [ ((0, 63),    "98951956F4BD5E2E9DC624CCD2D79E60"
                                       ++ "6D24A4DB51D413FDAF9A9741A6F079B4"
                                       ++ "21400FDA0B4D8785578BB318BDAD4ABC"
                                       ++ "A8C2D1BA3BA4E18C2F5572499F345BC1" )
                           , ((192, 255), "C3A267F0EB87ED714E09CABC2780FEF6"
                                       ++ "E5F665BBBBB44C8448D8EB42D88275CD"
                                       ++ "62AD759AAC9F4080F73993DE50FF94E8"
                                       ++ "34E2CF7B74A91E68B38EACE9C12922C2" )
                           , ((256, 319), "78BD0BB32A69E62362EE7E31F1DD9E96"
                                       ++ "CA6E196844EFD9459F270D612119DFA4"
                                       ++ "5DD1522967629143CECD585CFE62B7FD"
                                       ++ "9D1503A62A238C35A66595C49DD71575" )
                           , ((448, 511), "C17F946C14A492392A1C554993F406B2"
                                       ++ "EA806E4186D97FCB420C21FB4245A3DB"
                                       ++ "4EBA2BCB59D2C33CE2CD5044A79A96F9"
                                       ++ "5182112D9724E16AD9E965047DA71F05" )
                          ]
    , testVector256 "Set 5, vector# 63"  ("00000000000000000000000000000000"
                                       ++ "00000000000000000000000000000000")
                                          "0000000000000001"
                           [ ((0, 63),    "B47F96AA96786135297A3C4EC56A613D"
                                       ++ "0B80095324FF43239D684C57FFE42E1C"
                                       ++ "44F3CC011613DB6CDC880999A1E65AED"
                                       ++ "1287FCB11C839C37120765AFA73E5075" )
                           , ((192, 255), "97128BD699DDC1B4B135D94811B5D2D6"
                                       ++ "B2ADCBDC1ED8D3CF86ECF65A1750DE66"
                                       ++ "CA5F1C2ED350DC2F497396E029DBD4A0"
                                       ++ "6FDDA6238BE7D120DD41E9F19E6DEEA2" )
                           , ((256, 319), "FF8065AD901A2DFC5C01642A840F7593"
                                       ++ "AE032946058E54EA67300FBF7B928C20"
                                       ++ "3244EF546762BA640032B6A2514122DE"
                                       ++ "0CA969283F70CE21F981A5D668274F0D" )
                           , ((448, 511), "1309268BE548EFEC38D79DF4334CA949"
                                       ++ "AB15A2A1003E2B97969FE0CD74A16A06"
                                       ++ "5FE8691F03CBD0ECFCF6312F2EE0697F"
                                       ++ "44BD3BF3E60320B289CBF21B428C8922" )
                          ]
    , testVector256 "Set 6, vector#  0"  ("0053A6F94C9FF24598EB3E91E4378ADD"
                                       ++ "3083D6297CCF2275C81B6EC11467BA0D")
                                          "0D74DB42A91077DE"
                           [ ((0, 63),    "F5FAD53F79F9DF58C4AEA0D0ED9A9601"
                                       ++ "F278112CA7180D565B420A48019670EA"
                                       ++ "F24CE493A86263F677B46ACE1924773D"
                                       ++ "2BB25571E1AA8593758FC382B1280B71" )
                           , ((65472, 65535), "B70C50139C63332EF6E77AC54338A407"
                                       ++ "9B82BEC9F9A403DFEA821B83F7860791"
                                       ++ "650EF1B2489D0590B1DE772EEDA4E3BC"
                                       ++ "D60FA7CE9CD623D9D2FD5758B8653E70" )
                           , ((65536, 65599), "81582C65D7562B80AEC2F1A673A9D01C"
                                       ++ "9F892A23D4919F6AB47B9154E08E699B"
                                       ++ "4117D7C666477B60F8391481682F5D95"
                                       ++ "D96623DBC489D88DAA6956B9F0646B6E" )
                           , ((131008, 131071), "A13FFA1208F8BF50900886FAAB40FD10"
                                       ++ "E8CAA306E63DF39536A1564FB760B242"
                                       ++ "A9D6A4628CDC878762834E27A541DA2A"
                                       ++ "5E3B3445989C76F611E0FEC6D91ACACC" )
                          ]
    , testVector256 "Set 6, vector#  1"  ("0558ABFE51A4F74A9DF04396E93C8FE2"
                                       ++ "3588DB2E81D4277ACD2073C6196CBF12")
                                          "167DE44BB21980E7"
                           [ ((0, 63),    "3944F6DC9F85B128083879FDF190F7DE"
                                       ++ "E4053A07BC09896D51D0690BD4DA4AC1"
                                       ++ "062F1E47D3D0716F80A9B4D85E6D6085"
                                       ++ "EE06947601C85F1A27A2F76E45A6AA87" )
                           , ((65472, 65535), "36E03B4B54B0B2E04D069E690082C8C5"
                                       ++ "92DF56E633F5D8C7682A02A65ECD1371"
                                       ++ "8CA4352AACCB0DA20ED6BBBA62E177F2"
                                       ++ "10E3560E63BB822C4158CAA806A88C82" )
                           , ((65536, 65599), "1B779E7A917C8C26039FFB23CF0EF8E0"
                                       ++ "8A1A13B43ACDD9402CF5DF38501098DF"
                                       ++ "C945A6CC69A6A17367BC03431A86B3ED"
                                       ++ "04B0245B56379BF997E25800AD837D7D" )
                           , ((131008, 131071), "7EC6DAE81A105E67172A0B8C4BBE7D06"
                                       ++ "A7A8759F914FBEB1AF62C8A552EF4A4F"
                                       ++ "56967EA29C7471F46F3B07F7A3746E95"
                                       ++ "3D315821B85B6E8CB40122B96635313C" )
                          ]
    , testVector256 "Set 6, vector#  2"  ("0A5DB00356A9FC4FA2F5489BEE4194E7"
                                       ++ "3A8DE03386D92C7FD22578CB1E71C417")
                                          "1F86ED54BB2289F0"
                           [ ((0, 63),    "3FE85D5BB1960A82480B5E6F4E965A44"
                                       ++ "60D7A54501664F7D60B54B06100A37FF"
                                       ++ "DCF6BDE5CE3F4886BA77DD5B44E95644"
                                       ++ "E40A8AC65801155DB90F02522B644023" )
                           , ((65472, 65535), "C8D6E54C29CA204018A830E266CEEE0D"
                                       ++ "037DC47E921947302ACE40D1B996A6D8"
                                       ++ "0B598677F3352F1DAA6D9888F891AD95"
                                       ++ "A1C32FFEB71BB861E8B07058515171C9" )
                           , ((65536, 65599), "B79FD776542B4620EFCB88449599F234"
                                       ++ "03E74A6E91CACC50A05A8F8F3C0DEA8B"
                                       ++ "00E1A5E6081F5526AE975B3BC0450F1A"
                                       ++ "0C8B66F808F1904B971361137C93156F" )
                           , ((131008, 131071), "7998204FED70CE8E0D027B206635C08C"
                                       ++ "8BC443622608970E40E3AEDF3CE790AE"
                                       ++ "EDF89F922671B45378E2CD03F6F62356"
                                       ++ "529C4158B7FF41EE854B1235373988C8" )
                          ]
    , testVector256 "Set 6, vector#  3"  ("0F62B5085BAE0154A7FA4DA0F34699EC"
                                       ++ "3F92E5388BDE3184D72A7DD02376C91C")
                                          "288FF65DC42B92F9"
                           [ ((0, 63),    "5E5E71F90199340304ABB22A37B6625B"
                                       ++ "F883FB89CE3B21F54A10B81066EF87DA"
                                       ++ "30B77699AA7379DA595C77DD59542DA2"
                                       ++ "08E5954F89E40EB7AA80A84A6176663F" )
                           , ((65472, 65535), "2DA2174BD150A1DFEC1796E921E9D6E2"
                                       ++ "4ECF0209BCBEA4F98370FCE629056F64"
                                       ++ "917283436E2D3F45556225307D5CC5A5"
                                       ++ "65325D8993B37F1654195C240BF75B16" )
                           , ((65536, 65599), "ABF39A210EEE89598B7133377056C2FE"
                                       ++ "F42DA731327563FB67C7BEDB27F38C7C"
                                       ++ "5A3FC2183A4C6B277F901152472C6B2A"
                                       ++ "BCF5E34CBE315E81FD3D180B5D66CB6C" )
                           , ((131008, 131071), "1BA89DBD3F98839728F56791D5B7CE23"
                                       ++ "5036DE843CCCAB0390B8B5862F1E4596"
                                       ++ "AE8A16FB23DA997F371F4E0AACC26DB8"
                                       ++ "EB314ED470B1AF6B9F8D69DD79A9D750" )
                          ]
    ]
    where
        testVector256 name key iv = testVector name (salsa 20) (readHex key `asTypeOf` (undefined :: Key256)) (readHex iv) . map (\(a, b) -> (a, fromChunks [hexToByteString b]))