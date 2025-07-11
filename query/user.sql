-- name: GetUserByID :one
select * from users where id = ?;

-- name: GetAllUsers :many
select * from users;

-- name: GetIdByUsername :one
select id from users where username = ?;

-- name: LoginUser :one
select * from users where username = ?;

-- name: CreateUser :one
insert into users (username, password) values (?, ?) returning *;

-- name: ResetPassword :one
update users set password = ? where username = ? returning *;

-- name: DeleteUser :exec
delete from users where id = ?;
