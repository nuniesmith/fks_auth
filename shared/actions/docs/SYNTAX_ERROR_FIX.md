# Fixed Bash Syntax Errors in Destroy Workflow

## Issues Found and Fixed

### 1. **Missing `fi` Statement (Line ~1424)**
**Problem**: An `if-else` block was missing its closing `fi` statement.
```bash
# BROKEN:
if [[ "$TAILNET" == "-" ]]; then
  echo "⚠️ Using default tailnet"
  DEVICES_URL="https://api.tailscale.com/api/v2/devices"
else
  echo "🔍 Using tailnet: $TAILNET"
DEVICES_URL="https://api.tailscale.com/api/v2/tailnet/$TAILNET/devices"
# Missing fi here!

# FIXED:
if [[ "$TAILNET" == "-" ]]; then
  echo "⚠️ Using default tailnet"
  DEVICES_URL="https://api.tailscale.com/api/v2/devices"
else
  echo "🔍 Using tailnet: $TAILNET"
  DEVICES_URL="https://api.tailscale.com/api/v2/tailnet/$TAILNET/devices"
fi
```

### 2. **Undefined Variable References**
**Problem**: Multiple references to `$TAILSCALE_AUTH_KEY` which doesn't exist in the OAuth context.
```bash
# BROKEN:
-H "Authorization: Bearer $TAILSCALE_AUTH_KEY"

# FIXED:
-H "Authorization: Bearer $DESTROY_TOKEN"
# or
-H "Authorization: Bearer $CLEANUP_TOKEN"
```

### 3. **Duplicate/Orphaned Code Blocks**
**Problem**: There were duplicate cleanup code blocks causing confusion and syntax errors.
**Fix**: Removed the orphaned/duplicate sections that were causing parsing issues.

### 4. **Incorrect Indentation in Case Statement**
**Problem**: The `esac` statement was misaligned and there was a misplaced echo statement.
```bash
# BROKEN:
            echo "⚠️ No server found for ${{ env.SERVICE_NAME }}"
          fi
          ;;
        esac  # Wrong indentation

# FIXED:
          else
            echo "⚠️ No server found for ${{ env.SERVICE_NAME }}"
          fi
          ;;
          esac  # Correct indentation
```

## Root Cause Analysis

The syntax errors were introduced during the OAuth migration fixes due to:

1. **Complex nested conditionals** in cleanup sections
2. **Variable name changes** from auth keys to OAuth tokens that weren't updated everywhere
3. **Code duplication** during merging of different cleanup approaches
4. **Missing closing statements** when restructuring if/else blocks

## Verification

✅ **Syntax Check Passed**: The workflow file now has no syntax errors
✅ **Variable References Fixed**: All `$TAILSCALE_AUTH_KEY` replaced with correct OAuth tokens
✅ **Code Structure Cleaned**: Removed duplicate and orphaned code blocks
✅ **Indentation Corrected**: All bash statements properly aligned

## Next Steps

The destroy workflow should now run successfully. The key fixes ensure:

1. **Proper OAuth token usage** throughout cleanup sections
2. **Complete conditional blocks** with proper `fi` statements  
3. **Clean code structure** without duplicate blocks
4. **Correct bash syntax** with proper indentation

## Testing

To verify the fixes:
1. **Run the deployment** - The destroy job should now execute without syntax errors
2. **Check logs** - Look for successful OAuth token acquisition and device cleanup
3. **Verify server destruction** - Confirm servers are properly destroyed and cleaned up
