-- name: GetStoreByID :one
select * from stores where id = ?;

-- name: GetStoreByName :one
select * from stores where name = ?;

-- name: GetAllStores :many
select * from stores;

-- name: CreateStore :one
insert into stores (id, name, cover) values (?, ?, ?) returning *;

-- name: RenameStore :one
update stores set name = ? where id = ? returning *;

-- name: DeleteStore :exec
delete from stores where id = ?;
