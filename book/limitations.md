# Known Limitations

**Warning:** The implementation of SP1 Blobstream assumes that the number of validators is less than 
256. This limitation is due to the use of a 256-bit bitmap to represent whether a validator has 
signed off on a header. If the number of validators exceeds 256, the `validatorBitmap` functionality
may not work as intended, potentially leading to an incomplete validator equivocation. 

On Celestia, the number of validators is currently 100, and there are no plans to increase this number
significantly. If it was to be increased, the signature aggregation logic in the consensus protocol
would likely change as well, which would also necessitate a change in the SP1 Blobstream implementation.
