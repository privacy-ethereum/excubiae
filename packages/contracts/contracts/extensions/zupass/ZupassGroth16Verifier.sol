// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.8.20;

contract ZupassGroth16Verifier {
    // Scalar field size
    uint256 private constant r =
        21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617;
    // Base field size
    uint256 private constant q =
        21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583;

    // Verification Key data
    uint256 private constant alphax =
        20_491_192_805_390_485_299_153_009_773_594_534_940_189_261_866_228_447_918_068_658_471_970_481_763_042;
    uint256 private constant alphay =
        9_383_485_363_053_290_200_918_347_156_157_836_566_562_967_994_039_712_273_449_902_621_266_178_545_958;
    uint256 private constant betax1 =
        4_252_822_878_758_300_859_123_897_981_450_591_353_533_073_413_197_771_768_651_442_665_752_259_397_132;
    uint256 private constant betax2 =
        6_375_614_351_688_725_206_403_948_262_868_962_793_625_744_043_794_305_715_222_011_528_459_656_738_731;
    uint256 private constant betay1 =
        21_847_035_105_528_745_403_288_232_691_147_584_728_191_162_732_299_865_338_377_159_692_350_059_136_679;
    uint256 private constant betay2 =
        10_505_242_626_370_262_277_552_901_082_094_356_697_409_835_680_220_590_971_873_171_140_371_331_206_856;
    uint256 private constant gammax1 =
        11_559_732_032_986_387_107_991_004_021_392_285_783_925_812_861_821_192_530_917_403_151_452_391_805_634;
    uint256 private constant gammax2 =
        10_857_046_999_023_057_135_944_570_762_232_829_481_370_756_359_578_518_086_990_519_993_285_655_852_781;
    uint256 private constant gammay1 =
        4_082_367_875_863_433_681_332_203_403_145_435_568_316_851_327_593_401_208_105_741_076_214_120_093_531;
    uint256 private constant gammay2 =
        8_495_653_923_123_431_417_604_973_247_489_272_438_418_190_587_263_600_148_770_280_649_306_958_101_930;
    uint256 private constant deltax1 =
        4_794_378_188_555_673_810_018_158_797_263_945_613_117_081_424_700_154_854_974_240_721_894_252_090_534;
    uint256 private constant deltax2 =
        1_816_911_282_723_953_521_360_374_096_804_693_609_948_256_596_921_895_265_929_104_078_200_823_204_675;
    uint256 private constant deltay1 =
        4_822_598_240_965_235_353_021_859_310_978_490_456_254_180_072_341_966_996_061_361_969_858_340_984_511;
    uint256 private constant deltay2 =
        13_543_378_357_184_474_310_383_646_423_534_605_062_703_850_124_878_450_029_441_667_582_061_275_654_866;

    uint256 private constant IC0x =
        7_039_163_794_843_290_796_256_368_468_693_852_992_261_864_980_639_380_847_782_867_461_741_038_210_431;
    uint256 private constant IC0y =
        13_828_571_545_952_070_419_695_572_439_672_637_697_093_967_550_127_663_217_094_587_479_939_756_801_713;

    uint256 private constant IC1x =
        3_958_090_907_019_850_444_580_447_271_310_783_643_067_855_398_231_992_297_257_715_727_710_216_995_446;
    uint256 private constant IC1y =
        20_221_946_439_601_599_894_288_820_734_713_434_259_239_717_191_029_254_240_067_234_373_135_565_758_177;

    uint256 private constant IC2x =
        900_186_639_711_238_933_493_055_667_378_009_920_193_627_212_372_904_879_368_486_442_415_809_327_595;
    uint256 private constant IC2y =
        2_326_167_641_766_524_616_999_631_967_433_198_170_614_424_673_993_051_767_085_816_973_791_951_172_320;

    uint256 private constant IC3x =
        5_036_413_725_381_298_640_320_115_097_177_392_324_444_247_429_122_196_014_822_193_539_177_279_161_834;
    uint256 private constant IC3y =
        16_915_948_281_029_825_623_174_724_126_850_423_768_748_230_097_781_953_657_414_920_017_958_567_938_481;

    uint256 private constant IC4x =
        18_760_100_143_371_695_362_362_583_151_699_410_223_835_931_838_504_964_976_371_030_235_483_771_799_520;
    uint256 private constant IC4y =
        11_050_897_648_840_559_830_340_797_268_632_494_985_552_806_330_900_971_650_426_635_140_540_632_129_623;

    uint256 private constant IC5x =
        14_405_103_043_934_777_929_451_041_926_853_384_737_748_587_264_397_789_238_453_021_115_804_714_011_027;
    uint256 private constant IC5y =
        17_654_525_523_246_776_275_961_068_512_159_018_488_399_387_144_246_684_730_694_339_431_289_852_689_612;

    uint256 private constant IC6x =
        8_723_869_934_697_142_623_491_762_263_289_398_094_319_535_893_464_503_540_125_898_389_370_968_107_859;
    uint256 private constant IC6y =
        6_562_444_046_746_975_238_614_247_431_088_671_155_226_534_237_756_214_900_132_774_223_548_393_484_900;

    uint256 private constant IC7x =
        14_577_478_605_943_949_020_672_432_197_678_273_024_089_978_103_276_775_373_202_577_864_795_436_168_402;
    uint256 private constant IC7y =
        20_868_380_911_669_423_225_158_693_169_242_758_989_558_229_682_271_980_505_657_366_061_586_596_203_338;

    uint256 private constant IC8x =
        15_078_791_307_200_682_406_383_940_510_187_595_016_164_044_832_563_024_269_891_293_768_166_347_461_344;
    uint256 private constant IC8y =
        13_807_879_254_500_296_471_557_402_479_543_820_453_954_075_404_741_718_297_177_665_886_866_496_451_391;

    uint256 private constant IC9x =
        11_961_110_457_054_262_187_040_141_268_827_975_035_460_766_426_109_310_097_612_340_764_580_611_314_242;
    uint256 private constant IC9y =
        648_031_620_139_716_874_034_542_002_574_123_681_367_629_070_550_974_595_278_392_168_004_036_814_626;

    uint256 private constant IC10x =
        9_897_786_420_777_014_154_834_245_148_124_872_045_575_237_833_648_028_105_961_996_898_423_566_286_793;
    uint256 private constant IC10y =
        10_942_250_463_782_575_990_311_669_310_939_232_003_635_777_350_050_348_004_971_415_243_722_694_683_862;

    uint256 private constant IC11x =
        21_768_976_691_153_943_693_253_939_674_737_520_933_075_287_952_326_155_542_834_234_684_045_105_263_955;
    uint256 private constant IC11y =
        2_652_628_038_258_207_868_440_308_689_934_020_510_765_602_358_527_332_281_459_263_595_352_308_874_872;

    uint256 private constant IC12x =
        10_579_889_892_022_441_902_715_761_343_940_775_692_321_155_123_038_188_581_132_868_576_263_856_691_960;
    uint256 private constant IC12y =
        14_197_080_288_473_739_214_766_468_387_110_821_163_678_798_975_745_451_452_929_084_680_507_366_969_089;

    uint256 private constant IC13x =
        17_381_487_274_016_777_148_244_396_779_385_401_991_045_642_828_052_327_241_661_444_508_026_488_993_960;
    uint256 private constant IC13y =
        12_631_141_756_649_305_162_072_161_190_046_426_727_112_068_887_466_313_087_474_366_448_379_889_938_290;

    uint256 private constant IC14x =
        13_935_047_382_751_423_896_533_075_574_654_791_455_853_724_928_466_459_591_893_970_338_304_052_339_429;
    uint256 private constant IC14y =
        6_824_865_220_976_543_574_218_366_346_391_934_951_925_243_253_294_023_634_161_017_592_510_424_936_549;

    uint256 private constant IC15x =
        7_031_992_312_358_334_117_229_960_826_366_500_136_698_824_958_913_380_375_057_168_422_867_887_208_482;
    uint256 private constant IC15y =
        6_487_726_177_217_344_454_795_293_919_275_011_847_002_886_774_229_625_835_362_883_818_222_058_658_917;

    uint256 private constant IC16x =
        32_761_952_607_172_566_377_921_792_852_655_350_243_312_728_025_797_797_731_884_919_650_955_995_978;
    uint256 private constant IC16y =
        17_109_740_037_766_941_001_038_815_791_052_639_848_028_856_032_033_398_873_318_266_457_482_577_886_649;

    uint256 private constant IC17x =
        5_148_130_823_680_965_556_573_321_200_326_358_804_854_949_261_914_205_931_196_224_467_597_274_599_399;
    uint256 private constant IC17y =
        17_786_165_933_748_885_174_698_871_854_113_633_988_020_047_930_367_652_317_579_732_342_918_892_135_076;

    uint256 private constant IC18x =
        19_132_395_236_354_116_173_686_960_242_674_593_409_872_273_373_618_210_170_105_548_787_911_478_039_676;
    uint256 private constant IC18y =
        13_128_673_728_382_375_315_191_668_017_332_103_847_318_829_241_457_370_626_993_176_402_741_448_018_866;

    uint256 private constant IC19x =
        14_279_232_715_058_070_388_045_405_059_532_116_192_488_308_995_813_346_048_366_203_712_476_135_182_708;
    uint256 private constant IC19y =
        15_194_615_736_824_271_563_039_224_473_810_596_003_691_641_177_247_333_143_890_653_748_759_024_086_797;

    uint256 private constant IC20x =
        9_955_090_722_504_979_957_069_720_304_999_125_823_978_111_318_362_496_584_519_854_575_527_608_185_162;
    uint256 private constant IC20y =
        5_794_103_785_028_496_675_031_047_406_750_626_512_072_617_762_810_766_655_823_567_669_958_439_141_907;

    uint256 private constant IC21x =
        3_093_386_023_754_979_021_969_916_793_626_732_114_241_059_635_051_234_406_414_231_194_529_079_272_032;
    uint256 private constant IC21y =
        2_726_333_648_975_816_401_517_500_089_384_058_227_785_233_536_677_037_001_841_489_035_806_732_587_931;

    uint256 private constant IC22x =
        5_277_410_462_435_782_523_915_882_980_275_775_886_349_488_617_157_850_699_431_034_750_288_036_800_613;
    uint256 private constant IC22y =
        21_607_346_138_964_363_953_763_925_149_731_352_915_511_002_970_774_217_667_749_452_112_345_555_034_956;

    uint256 private constant IC23x =
        2_882_073_216_919_257_197_946_498_011_741_429_525_374_768_355_767_062_401_579_097_340_303_609_014_667;
    uint256 private constant IC23y =
        13_336_208_254_651_518_889_575_781_043_861_573_326_120_722_149_864_211_966_571_295_065_261_003_981_732;

    uint256 private constant IC24x =
        16_518_085_772_523_452_403_713_249_212_239_346_119_989_769_943_791_821_955_471_370_367_814_804_849_274;
    uint256 private constant IC24y =
        3_163_851_008_551_205_343_892_721_959_924_291_514_513_839_424_028_748_364_301_581_737_083_684_712_635;

    uint256 private constant IC25x =
        21_443_140_829_801_323_335_830_440_272_589_422_531_303_604_169_183_393_653_690_045_415_169_893_110_317;
    uint256 private constant IC25y =
        11_843_677_807_581_613_645_245_376_500_039_550_313_868_511_109_982_120_780_557_566_436_801_551_936_632;

    uint256 private constant IC26x =
        9_011_343_512_724_109_228_637_988_929_452_301_928_814_416_148_302_399_365_691_495_043_540_007_452_711;
    uint256 private constant IC26y =
        19_203_719_374_228_430_540_624_285_138_844_258_546_893_532_214_993_666_117_722_702_463_877_026_204_624;

    uint256 private constant IC27x =
        12_282_563_786_492_051_221_220_863_019_504_107_834_872_987_144_162_405_093_912_833_624_832_473_504_126;
    uint256 private constant IC27y =
        2_098_404_497_662_286_606_968_957_419_285_970_045_028_044_455_644_658_720_985_187_205_946_176_225_636;

    uint256 private constant IC28x =
        1_990_701_565_738_088_758_270_472_967_471_263_340_707_808_628_204_302_356_692_995_713_089_340_295_959;
    uint256 private constant IC28y =
        4_710_902_959_112_092_813_812_405_997_875_645_709_469_153_185_247_079_786_406_984_810_436_621_334_836;

    uint256 private constant IC29x =
        20_358_882_933_388_981_503_171_778_761_697_392_336_011_378_779_059_025_555_927_722_043_477_769_063_258;
    uint256 private constant IC29y =
        19_015_855_458_316_650_610_909_766_042_056_506_990_773_552_974_154_423_789_621_320_056_338_171_324_109;

    uint256 private constant IC30x =
        20_882_010_929_117_143_317_945_388_885_678_484_675_687_595_287_997_043_750_607_534_940_060_968_021_588;
    uint256 private constant IC30y =
        11_586_557_172_082_174_037_613_559_244_105_184_201_710_114_582_175_280_732_260_566_723_406_709_924_275;

    uint256 private constant IC31x =
        9_866_308_320_093_007_323_457_785_354_472_236_077_116_309_736_444_536_950_583_247_217_505_300_484_593;
    uint256 private constant IC31y =
        7_621_726_862_256_096_662_846_253_511_430_079_218_096_624_239_819_015_602_672_239_587_875_065_773_680;

    uint256 private constant IC32x =
        14_027_123_489_779_385_457_612_700_332_560_563_436_358_522_575_256_251_872_455_086_560_940_806_515_518;
    uint256 private constant IC32y =
        10_938_955_322_537_907_189_548_948_078_384_029_109_133_599_816_409_669_950_598_646_265_343_304_376_683;

    uint256 private constant IC33x =
        8_185_779_524_540_657_541_561_125_117_577_265_603_809_435_796_152_263_318_353_366_879_537_563_587_361;
    uint256 private constant IC33y =
        7_022_890_698_869_206_227_386_505_409_956_869_964_786_133_909_878_013_184_769_185_704_625_348_906_859;

    uint256 private constant IC34x =
        11_611_413_113_751_908_909_193_648_245_064_739_218_553_980_961_929_170_910_199_270_975_967_104_957_038;
    uint256 private constant IC34y =
        18_994_807_587_760_619_856_245_913_328_685_591_005_051_029_724_453_337_667_407_306_111_138_944_756_694;

    uint256 private constant IC35x =
        200_383_746_952_988_761_639_379_177_517_104_787_510_472_386_926_528_110_614_397_950_418_667_358_661;
    uint256 private constant IC35y =
        20_007_848_431_425_763_869_830_663_340_890_269_703_980_870_987_344_402_378_604_194_352_912_831_137_056;

    uint256 private constant IC36x =
        328_413_860_030_399_674_842_447_170_312_944_751_562_586_291_423_774_720_425_356_928_068_580_343_472;
    uint256 private constant IC36y =
        5_189_648_959_630_633_293_821_012_021_210_812_639_351_882_790_811_543_893_302_480_708_749_969_871_675;

    uint256 private constant IC37x =
        6_012_328_917_803_371_026_931_141_367_320_642_434_394_368_982_571_440_096_775_691_385_288_621_172_219;
    uint256 private constant IC37y =
        3_144_007_704_082_241_276_171_331_516_247_837_779_546_266_689_067_323_035_946_808_770_824_524_079_278;

    uint256 private constant IC38x =
        6_432_946_433_062_452_526_687_536_616_554_972_830_856_614_963_273_241_146_116_338_471_741_671_687_252;
    uint256 private constant IC38y =
        15_585_047_391_247_849_588_392_219_751_347_369_098_681_511_169_371_119_693_472_990_059_654_876_497_118;

    // Memory data
    uint16 private constant pVk = 0;
    uint16 private constant pPairing = 128;

    uint16 private constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[38] calldata _pubSignals
    )
        public
        view
        returns (bool)
    {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))

                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))

                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))

                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))

                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))

                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))

                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))

                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))

                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))

                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))

                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))

                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))

                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))

                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))

                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))

                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))

                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))

                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))

                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))

                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))

                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))

                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))

                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))

                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))

                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            checkField(calldataload(add(_pubSignals, 416)))

            checkField(calldataload(add(_pubSignals, 448)))

            checkField(calldataload(add(_pubSignals, 480)))

            checkField(calldataload(add(_pubSignals, 512)))

            checkField(calldataload(add(_pubSignals, 544)))

            checkField(calldataload(add(_pubSignals, 576)))

            checkField(calldataload(add(_pubSignals, 608)))

            checkField(calldataload(add(_pubSignals, 640)))

            checkField(calldataload(add(_pubSignals, 672)))

            checkField(calldataload(add(_pubSignals, 704)))

            checkField(calldataload(add(_pubSignals, 736)))

            checkField(calldataload(add(_pubSignals, 768)))

            checkField(calldataload(add(_pubSignals, 800)))

            checkField(calldataload(add(_pubSignals, 832)))

            checkField(calldataload(add(_pubSignals, 864)))

            checkField(calldataload(add(_pubSignals, 896)))

            checkField(calldataload(add(_pubSignals, 928)))

            checkField(calldataload(add(_pubSignals, 960)))

            checkField(calldataload(add(_pubSignals, 992)))

            checkField(calldataload(add(_pubSignals, 1024)))

            checkField(calldataload(add(_pubSignals, 1056)))

            checkField(calldataload(add(_pubSignals, 1088)))

            checkField(calldataload(add(_pubSignals, 1120)))

            checkField(calldataload(add(_pubSignals, 1152)))

            checkField(calldataload(add(_pubSignals, 1184)))

            checkField(calldataload(add(_pubSignals, 1216)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
