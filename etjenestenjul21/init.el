(require 'subr-x)
(require 'seq)

(defvar *noise* "Ë̛͙̾̂͝T̡̻͒᷁͒J̴̵͉̞͔̀{̧̘̃̉̉᷍G̸͉̠⃬̒N̼̝᷾̽͒̈́Ű̼⃭̤͛̈́ ͖⃬̾̄̄́T⃘̸͍⃕́̈U⃯̥⃔⃗̇᷍L̼᷁̑᷀͠L⃒̘̜⃰᷇̕Ẻ͈⃔⃕͝R̛̘͓⃑̓̽ ͕᷀͊͑̒︤D͇̘̲᷇⃡Ư⃯̱⃕͛͟ ⃓̭⃯⃮᷆᷁V̨̟̯᷿̘⃐E᷿͖⃜᷾̾L̪͍⃛̑᷇?⃓͙⃑̈͌᷾\͓̰̆̏⃗!⃚͚͕̰᷊͍̓̀᷈̑͒͘🕵̘̹͋̑͗͠}̐⃡̀͌͆͡")

(defun denoise (sequence)
  (thread-last sequence
    (seq-filter (lambda (c) (< c 255)))
    (mapcar 'string)
    (string-join)))

(defun check-sanity ()
  (when (member (getenv "EDITOR")
                '("vi" "vim" "code" "nano"))
    (let* ((less-noisy (denoise *noise*))
           (prefix (seq-subseq less-noisy 0 3)))
      (with-current-buffer "*scratch*"
        (insert
         (mapconcat 'string
                    (append (mapcar 'downcase prefix)
                            (nthcdr 3 (string-to-list less-noisy)))
                    ""))))))

(check-sanity)