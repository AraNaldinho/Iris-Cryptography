def moveZeroes(self, nums):
        i, l = 0, 0
        while i < len(nums):
            if nums[i] != 0:
                nums[i], nums[l] = nums[l], nums[i]
                l += 1
            i += 1