# UIUCTF 2021 osint Suite

## Basic info

* Title - Chaplin's PR Nightmare
* Chal Count - 8
* Chal Distribution
  * Twitter (Sanity)
  * Youtube (Easy)
  * Website (Easy)
  * Website (Medium)
  * Imgur (Medium)
  * Linkedin (Hard)
  * Github (Hard)
  * Google Reviews (Hard)

## Detailed information

* Twitter
  * Flag hidden in a collection of content that the person likes. (List)
  * <https://twitter.com/ChaplinCoding>
    * /lists
  * FLAG=uiuctf{pe@k_c0medy!}
* Youtube
  * Linked from the twitter, flag will be in the video linked in the background of a charlie chaplin old recordings
  * FLAG=uiuctf{ch@pLin_oN_th3_tV!!}
* Website
  * Linked from about page, the first flag will be at the end of a carousel of images
  * FLAG=uiuctf{ch@pl1n_i5_eL337}
* Website - medium
  * Find link at bottom of the page to the additional information page, fill out form and get flag as response
  * FLAG=uiuctf{w3_d0_nOt_v@lu3_yoUR_1nPuT}
* Imgur
  * One of the images is an imgur image from the account, the other image on the account has the flag
  * FLAG=uiuctf{tH3_pR_p0Lic3_h@vE_cAugHt_Up?!}
* Linkedin
  * Linked from charliechaplin.dev is a linkedin page. The page will host an event
  * FLAG=uiuctf{pr0f3s5iOn@l_bUs1n3sS_envIroNm3n7}
* Github
  * Linked from a post on the linkedin is the charlie chaplin github page. It will have a reverted commit or PR or issue or something like that with on GH
  * uiuctf{th3_TrUe_pR_N1gHtm@r3}
* Google Reviews
  * Inspired by last years feedback, can take email from github issue, plug it in and get gmail ID.
  * Find reviews for businesses, one of them is flag.
