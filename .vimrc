function! RunCMake()
  execute 'terminal'
  call feedkeys("cd ./build/Debug\<CR>")
  call feedkeys("cmake -DCMAKE_BUILD_TYPE=Debug ../..\<CR>")
  call feedkeys("cmake --build .\<CR>")
  call feedkeys("exit\<CR>")
endfunction

function! RunProgram()
    execute 'terminal'
    call feedkeys("./bin/Debug/dnscli www.amazon.com\<CR>")
endfunction

function! ChangePrevCommit()
    execute 'terminal'
    call feedkeys("git add -u\<CR>")
    call feedkeys("git status\<CR>")
    call feedkeys("git commit --amend --no-edit\<CR>")
    call feedkeys("git push -f && sleep 2\<CR>")
    call feedkeys("exit\<CR>")
endfunction

nnoremap <F5> :call RunCMake()<CR>
nnoremap <F6> :call RunProgram()<CR>
nnoremap <F3> :call ChangePrevCommit()<CR>

