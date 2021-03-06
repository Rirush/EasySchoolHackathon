package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"io"
)

var db *sqlx.DB

var schema = `
CREATE TABLE IF NOT EXISTS credentials (
	uuid text primary key not null,
	email text unique not null,
	password text not null
);

CREATE TABLE IF NOT EXISTS sessions (
    user text references credentials not null,
    token text unique not null
);

CREATE TABLE IF NOT EXISTS profiles (
 	user text unique references credentials not null,
 	first_name text not null,
 	last_name text not null,
 	birth_date text not null,
 	bio text not null
);

CREATE TABLE IF NOT EXISTS profile_pictures (
    uuid text primary key not null,
    user text references credentials not null,
    data blob not null,
    is_primary boolean not null
);

CREATE TABLE IF NOT EXISTS tags (
    tag text not null,
    user text references credentials not null
);

CREATE TABLE IF NOT EXISTS matches (
    matcher text references credentials not null,
    matchee text references credentials not null,
    likes boolean not null
);

CREATE TABLE IF NOT EXISTS posts (
    sender text references credentials not null,
    contents text not null,
    tag text not null
);

CREATE TABLE IF NOT EXISTS messages (
    sender text references credentials not null,
    target text references credentials not null,
    contents text not null
)
`

type Credentials struct {
	UUID uuid.UUID
	Email string
	Password string
}

func FindCredentialsByEmail(email string) (*Credentials, error) {
	row := db.QueryRowx("SELECT * FROM credentials WHERE email = ?", email)
	cred := &Credentials{}
	err := row.StructScan(cred)
	return cred, err
}

func (c *Credentials) Update() error {
	_, err := db.NamedExec("UPDATE credentials SET email = :email, password = :password WHERE uuid = :uuid", *c)
	return err
}

func (c *Credentials) Insert() error {
	c.UUID = uuid.New()
	_, err := db.NamedExec("INSERT INTO credentials VALUES (:uuid, :email, :password)", *c)
	return err
}

type Session struct {
	User uuid.UUID
	Token string
}

func GenerateSession(user uuid.UUID) (*Session, error) {
	rawToken := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, rawToken)
	if err != nil {
		return nil, err
	}
	token := hex.EncodeToString(rawToken)
	session := &Session{
		User: user,
		Token: token,
	}
	_, err = db.NamedExec("INSERT INTO sessions VALUES (:user, :token)", *session)
	return session, err
}

func ValidateSession(token string) (uuid.UUID, error) {
	row := db.QueryRowx("SELECT user FROM sessions WHERE token = ?", token)
	user := uuid.UUID{}
	err := row.Scan(&user)
	return user, err
}

type Profile struct {
	User uuid.UUID
	FirstName string `db:"first_name"`
	LastName string `db:"last_name"`
	BirthDate string `db:"birth_date"`// DD.MM.YYYY
	Bio string
}

func (p *Profile) Insert() error {
	_, err := db.NamedExec("INSERT INTO profiles VALUES (:user, :first_name, :last_name, :birth_date, :bio)", *p)
	return err
}

func (p *Profile) Update() error {
	_, err := db.NamedExec("UPDATE profiles SET first_name = :first_name, last_name = :last_name, birth_date = :birth_date, bio = :bio WHERE user = :user", *p)
	return err
}

func FindProfileByID(id uuid.UUID) (*Profile, error) {
	row := db.QueryRowx("SELECT * FROM profiles WHERE user = ?", id)
	p := &Profile{}
	err := row.StructScan(p)
	return p, err
}

type ProfilePicture struct {
	UUID uuid.UUID
	User uuid.UUID
	Data []byte
	IsPrimary bool `db:"is_primary"`
}

func (p *ProfilePicture) Insert() error {
	p.UUID = uuid.New()
	_, err := db.NamedExec("INSERT INTO profile_pictures VALUES (:uuid, :user, :data, :is_primary)", *p)
	return err
}

func (p *ProfilePicture) Delete() error {
	_, err := db.NamedExec("DELETE FROM profile_pictures WHERE uuid = :uuid", *p)
	return err
}

func (p *ProfilePicture) SetPrimary() error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	_, err = tx.Exec("UPDATE profile_pictures SET is_primary = false WHERE user = ?", p.User)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	_, err = tx.Exec("UPDATE profile_pictures SET is_primary = true WHERE uuid = ?", p.UUID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	p.IsPrimary = true
	err = tx.Commit()
	return err
}

func GetPictureByID(id uuid.UUID) (*ProfilePicture, error) {
	row := db.QueryRowx("SELECT * FROM profile_pictures WHERE uuid = ?", id)
	pic := &ProfilePicture{}
	err := row.StructScan(pic)
	return pic, err
}

func GetPicturesForUser(user uuid.UUID) ([]*ProfilePicture, error) {
	rows, err := db.Queryx("SELECT * FROM profile_pictures WHERE user = ?", user)
	if err == sql.ErrNoRows {
		return []*ProfilePicture{}, nil
	} else if err != nil {
		return nil, err
	}
	var pics []*ProfilePicture
	for rows.Next() {
		pic := &ProfilePicture{}
		err = rows.StructScan(pic)
		if err != nil {
			return nil, err
		}
		pics = append(pics, pic)
	}
	return pics, nil
}

type Tag struct {
	Tag string
	User uuid.UUID
}

func GetTagsForUser(user uuid.UUID) ([]*Tag, error) {
	rows, err := db.Queryx("SELECT DISTINCT(tag), user FROM tags WHERE user = ?", user)
	if err == sql.ErrNoRows {
		return []*Tag{}, nil
	} else if err != nil {
		return nil, err
	}
	var tags []*Tag
	for rows.Next() {
		tag := &Tag{}
		err = rows.StructScan(tag)
		if err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func SetTagsForUser(user uuid.UUID, tags []string) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM tags WHERE user = ?", user)
	if err != nil {
		// if this fails, we're screwed
		_ = tx.Rollback()
		return err
	}
	for _, tag := range tags {
		_, err = tx.Exec("INSERT INTO tags VALUES (?, ?)", tag, user)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	err = tx.Commit()
	return err
}

func FindUsersForTag(tag string) ([]uuid.UUID, error) {
	rows, err := db.Queryx("SELECT DISTINCT(user) FROM tags WHERE tag = ?", tag)
	if err == sql.ErrNoRows {
		return []uuid.UUID{}, nil
	} else if err != nil {
		return nil, err
	}
	var result []uuid.UUID
	for rows.Next() {
		user := uuid.UUID{}
		err = rows.Scan(&user)
		if err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, nil
}

type Match struct {
	Matcher uuid.UUID
	Matchee uuid.UUID
	Likes bool
}

func (m *Match) Insert() error {
	_, err := db.NamedExec("INSERT INTO matches VALUES (:matcher, :matchee, :likes)", *m)
	return err
}

func FindMatch(matcher, matchee uuid.UUID) (*Match, error) {
	row := db.QueryRowx("SELECT DISTINCT(matcher), matchee FROM matches WHERE matcher = ? AND matchee = ?", matcher, matchee)
	match := &Match{}
	err := row.StructScan(match)
	return match, err
}

func FindMatchesForMatchee(matchee uuid.UUID) ([]*Match, error) {
	rows, err := db.Queryx("SELECT * FROM matches WHERE matchee = ? AND likes = true", matchee)
	if err == sql.ErrNoRows {
		return []*Match{}, nil
	} else if err != nil {
		return nil, err
	}
	var matches []*Match
	for rows.Next() {
		match := &Match{}
		err := rows.StructScan(match)
		if err != nil {
			return nil, err
		}
		matches = append(matches, match)
	}
	return matches, nil
}

type Post struct {
	Sender uuid.UUID
	Contents string
	Tag string
}

func (p *Post) Insert() error {
	_, err := db.NamedExec("INSERT INTO posts VALUES (:sender, :contents, :tag)", *p)
	return err
}

func GetPostsForTag(tag string) ([]*Post, error) {
	rows, err := db.Queryx("SELECT * FROM posts WHERE tag = ?", tag)
	if err == sql.ErrNoRows {
		return []*Post{}, nil
	} else if err != nil {
		return nil, err
	}
	var result []*Post
	for rows.Next() {
		post := &Post{}
		err = rows.StructScan(post)
		if err != nil {
			return nil, err
		}
		result = append(result, post)
	}
	return result, nil
}

type Message struct {
	Sender uuid.UUID
	Target uuid.UUID
	Contents string
}

func (m *Message) Insert() error {
	_, err := db.NamedExec("INSERT INTO messages VALUES (:sender, :target, :contents)", *m)
	return err
}

func GetMessagesInConversation(a, b uuid.UUID) ([]*Message, error) {
	rows, err := db.Queryx("SELECT * FROM messages WHERE (sender = ? AND target = ?) OR (sender = ? AND target = ?)", a, b, b, a)
	if err == sql.ErrNoRows {
		return []*Message{}, nil
	} else if err != nil {
		return nil, err
	}
	var res []*Message
	for rows.Next() {
		message := &Message{}
		err := rows.StructScan(message)
		if err != nil {
			return nil, err
		}
		res = append(res, message)
	}
	return res, nil
}

func LoadDatabase(path string) error {
	var err error
	db, err = sqlx.Connect("sqlite3", fmt.Sprintf("file:%s?_journal=WAL", path))
	if err != nil {
		return err
	}
	_, err = db.Exec(schema)
	if err != nil {
		return err
	}
	return nil
}

func Close() {
	db.Close()
}