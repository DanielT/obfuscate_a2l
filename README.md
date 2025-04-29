# Obfuscate an a2l file and the matching elf file

## Elf file

- discard all sections for code and data, keeping only the debug info
- discard all line number debug info
- replace the names of types and variables in the debug info with random strings
- randomize addresses of variables

## a2l file

- rename all AXIS_PTS, CHARACTERISTIC, MEASUREMENT, RECORD_LAYOUT, FUNCTION, GROUP, COMPU_METHOD, COMPU_TAB with randomized names
- update all SYMBOL_LINK to use the updated names from the randomized debug info
- set all addresses to zero

## Todo

- Handle TYPEDEF_*, BLOB, INSTANCE in the a2l
- sort the output to eliminate the original ordering
- also zero the addresses in IF_DATA / CANAPE_EXT
