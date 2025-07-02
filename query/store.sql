-- name: GetStoreByID :one
select * from stores where id = $1;

-- name: GetStoreByName :one
select * from stores where name = $1;

-- name: GetAllStores :many
select * from stores;

-- name: CreateStore :one
insert into stores (id, name, cover) values ($1, $2, $3) returning *;

-- name: RenameStore :one
update stores set name = $2 where id = $1 returning *;

-- name: DeleteStore :exec
delete from stores where id = $1;
