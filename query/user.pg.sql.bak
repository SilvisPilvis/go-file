-- name: GetUserByID :one
select * from users where id = $1;

-- name: GetAllUsers :many
select * from users;

-- name: GetIdByUsername :one
select id from users where username = $1;

-- name: LoginUser :one
select * from users where username = $1;

-- name: CreateUser :one
insert into users (username, password) values ($1, $2) returning *;

-- name: ResetPassword :one
update users set password = $2 where username = $1 returning *;

-- name: DeleteUser :exec
delete from users where id = $1;
